from datetime import timedelta, datetime
from sqlalchemy import case
import json

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Path,Query
from fastapi.responses import JSONResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from fastapi.security import HTTPBearer

from config.db import get_db
from models.ticket_model import Ticket
from models.machine_model import Machine 
from models.user_model import User, Role
from models.solicitud_model import Solicitud
from schemas.ticket_schema import (
    TicketCreate, 
    TicketData, 
    TicketAssign, 
    TicketStateUpdate, 
    TicketResponse, 
    TicketSearchResponse,
    TicketSolicitudInfo,
    TicketCloseInfo
)

bearer_scheme = HTTPBearer()

# Crear un router para los tickets
ticket_router = APIRouter(tags=["Tickets"],prefix="/tickets")

# Crear un ticket (POST)
@ticket_router.post(
    "/ticket",
    summary="Crear un ticket como solicitud de revision",
    description="""Solicitar una revisión de una maquina a traves de un ticket, 
    crea un nuevo ticket con el estado predeterminado 'pendiente'.""",
    response_model=TicketResponse
)
async def create_ticket(
    request: Request = None,
    ticket: TicketCreate = None,
    db: Session = Depends(get_db),
    dependencies = Depends(HTTPBearer())
):
    """
    Crea un nuevo ticket con el estado predeterminado 'pendiente'.
    
    Parámetros:
        ticket: Los datos del ticket a crear, descripción, id de la máquina a la que 
            pertenece el ticket y prioridad (description, machine, priority).
    
    Retorna:
        Datos del ticket creado.
    """
    # Verificar si la máquina existe en la base de datos
    machine = db.query(Machine).filter(Machine.id == ticket.machine).first()
    if not machine:
        raise HTTPException(status_code=404, detail="La máquina con el serial proporcionado no existe.")

    user_info = request.state.user  
    user_id = user_info.get("sub")
    
    # Validar que el usuario existe en la base de datos
    creator = db.query(User).filter(User.id == user_id).first()
    if not creator:
        raise HTTPException(status_code=404, detail="Usuario creador no encontrado.")


    priority_deadlines = {
        'baja': timedelta(weeks=1),
        'media': timedelta(days=3),
        'alta': timedelta(days=1)
    }

    if ticket.priority not in priority_deadlines:
        raise HTTPException(status_code=400, detail="Prioridad no válida.")

    # Calcular el deadline según la prioridad
    deadline = datetime.now() + priority_deadlines[ticket.priority]
    
    # Crear el ticket si la máquina existe
    new_ticket = Ticket(
        description=ticket.description,
        state="pendiente",  
        machine_id=machine.id,
        priority=ticket.priority,
        created_by=user_id,
        created_at=func.now(), 
        deadline=deadline
    )

    db.add(new_ticket)
    db.commit()
    db.refresh(new_ticket)
    
    # Retornar la información del ticket creado
    return TicketResponse(
        id=new_ticket.id,
        description=new_ticket.description,
        state=new_ticket.state,
        created_at=new_ticket.created_at,
        priority=new_ticket.priority, 
        deadline=new_ticket.deadline,
        machine_id=machine.id,  
        created_by=creator.id
    )

@ticket_router.get(
    "/ticket/{ticket_id}", 
    summary="Obtener un ticket por su ID",
    description="Obtiene un ticket por su ID, incluyendo los nombres completos y los IDs de las personas involucradas.",
    response_model=TicketSearchResponse
)
async def get_ticket(
    ticket_id: int = Path(..., title="ID del ticket a buscar"), 
    db: Session = Depends(get_db), 
    dependencies=Depends(bearer_scheme)
):
    """
    Obtiene un ticket por su ID, incluyendo los nombres completos y los IDs de las personas involucradas.
    """
    # Unimos el ticket con la máquina y los usuarios (creador y asignado) para obtener la información necesaria
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()

    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")

    # Obtener el creador del ticket
    creator = db.query(User).filter(User.id == ticket.created_by).first()
    if not creator:
        raise HTTPException(status_code=404, detail="Usuario creador no encontrado")
    created_by_name = f"{creator.first_name} {creator.last_name}"

    # Obtener el usuario asignado (si existe)
    assigned_to_name = None
    assigned_to_id = None
    if ticket.assigned_to:
        assigned_user = db.query(User).filter(User.id == ticket.assigned_to).first()
        if assigned_user:
            assigned_to_name = f"{assigned_user.first_name} {assigned_user.last_name}"
            assigned_to_id = assigned_user.id

    # Devolver la respuesta con los nombres completos y los IDs
    return TicketSearchResponse(
        id=ticket.id,
        description=ticket.description,
        state=ticket.state,
        priority=ticket.priority,
        machine_serial=ticket.machine.serial,
        created_by_id=creator.id, 
        created_by_name=created_by_name,  
        assigned_to_id=assigned_to_id, 
        assigned_to_name=assigned_to_name, 
        created_at=ticket.created_at,
        deadline=ticket.deadline
    )

@ticket_router.patch(
    "/ticket/assing/{ticket_id}",
    summary="Asignar un responsable a un ticket",
    description="""Puede autoasignarse el ticket o asignarlo a otra persona si es un jefe de mantenimiento
    si no es omitido se verifica que el usuario sea un jefe de mantenimiento, que es el 
    unico con el poder de asignarle un ticket a otro usuario."""
)
async def assign_ticket(
    req : Request,
    ticket_id : str = Path(..., title="ID del ticket a asignar"),
    user_id: Optional[str] = Query(None, title="Usuario al que se le asigna el ticket"), 
    db: Session = Depends(get_db),
    token: str = Depends(bearer_scheme)
):
    """
    Asignar un responsable de atencion del ticket:
    Si se omite el parametro user_id se autoasigna la responsabilidad del ticket,
    si no es omitido se verifica que el usuario sea un jefe de mantenimiento, que es el
    unico con el poder de asignarle un ticket a otro usuario.
    
    Parámetros:
        ticket_id: ID del ticket a editar
        user_id: el id de la persona a la cual se le asiganara el ticket (assigned_to).
    
    Retorna:
       Información del ticket actualizado.
    """
    
    user_to_assing = None
    
    if user_id  != None:
        aux_user = req.state.user
        
        if aux_user.get("scopes") != 4:
            raise HTTPException(status_code=400,detail="No tienes permiso para realizar esta accion (No eres jefe de mantenimiento)")
        user_to_assing = user_id
    else:
        user_to_assing = req.state.user.get("sub")
        
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    
    if ticket.state == "finalizado":
        raise HTTPException(status_code=400, detail="No se puede asignar otro estado a un ticket finalizado")
    
    user = db.query(User).filter(User.id == user_to_assing).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuario al que se le asignara el ticket no encontrado")
    
    ticket.assigned_to = user.id
    db.commit()
    db.refresh(ticket)
    
    return  TicketSearchResponse(
        id=ticket.id,
        description=ticket.description,
        state=ticket.state,
        priority=ticket.priority,
        created_by_id= ticket.created_by,
        assigned_to_id= ticket.assigned_to,
        created_at=ticket.created_at,
    )

@ticket_router.patch(
    "/ticket/{ticket_id}/{ticket_state}",
    summary="Cambiar el estado de un ticket",
    description="""Cambia el estado de un ticket (a excepción de finalizado o en caso de que ya esté finalizado)
    Los estados validos son: asignado, en proceso, pendiente""",
    response_model=TicketSearchResponse
)
async def change_ticket_state(
    req:Request,
    ticket_id: int = Path(..., title="ID del ticket a editar"),
    ticket_state: str = Path(..., title="Estado al que se va a cambiar el ticket"), 
    db: Session = Depends(get_db),
    dependencies = Depends(bearer_scheme)    
):
    """
    Cambia el estado de un ticket (a excepción de finalizado o en caso de que ya esté finalizado) 

    Parámetros:
    - ticket_id: ID del ticket a editar
    - ticket_update: el estado al cual va a cambiar el ticket (state).
    - db: Sesión de la base de datos. (Dependencia)
    
    Retorna:
    - Información del ticket actualizado.
    """
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()

    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")

    if ticket_state not in ["asignado", "en proceso", "pendiente"]:
        raise HTTPException(status_code=400, detail="Estado no válido para cambio directo.")

    user  = req.state.user
    
    if ticket.assigned_to != user.get("sub"):
        raise HTTPException(status_code=400, detail="No tienes permiso para realizar esta accion (No eres el responsable del ticket)")


    # Obtener el nombre completo del creador del ticket
    creator = db.query(User).filter(User.id == ticket.created_by).first()

    # Actualizar el estado del ticket
    ticket.state = ticket_state
    db.commit()
    db.refresh(ticket)

    return  TicketSearchResponse(
        id=ticket.id,
        description=ticket.description,
        state=ticket.state,
        priority=ticket.priority,
        created_by_id= ticket.created_by,
        assigned_to_id= ticket.assigned_to,
        created_at=ticket.created_at,
    )
    
@ticket_router.post(
    "/ticket/solicitar-cierre/{ticket_id}",
    summary="Solicitar cierre de un ticket",
    description="""Solicitar el cierre de un ticket si el estado está en proceso. Solo el creador del ticket puede hacerlo.""",
    response_model=TicketSolicitudInfo
)
async def request_ticket_closure(
    req: Request,
    ticket_id: int = Path(..., title="ID del ticket a solicitar cierre"),
    close_info: TicketCloseInfo = None,
    db: Session = Depends(get_db),
    token: str = Depends(bearer_scheme)
):
    """
    Permite que el creador de un ticket solicite su cierre si está en estado 'en proceso'.
    El ticket pasará a estado 'pendiente a revisión' y se creará una solicitud de cierre.
    """
    # Obtener el ticket desde la base de datos
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()

    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")

    # Verificar si ya existe una solicitud de cierre pendiente para este ticket
    solicitud_existente = db.query(Solicitud).filter(
        Solicitud.ticket_id == ticket_id, 
        Solicitud.type == "cierre",
        Solicitud.status == "pendiente"
    ).first()

    if solicitud_existente:
        raise HTTPException(status_code=400, detail="Ya existe una solicitud de cierre pendiente para este ticket.")

    if ticket.state != "en proceso":
        raise HTTPException(status_code=400, detail="El ticket no está en estado 'en proceso'.")

    user_id = req.state.user.get("sub")
    
    if ticket.created_by != user_id:
        raise HTTPException(status_code=403, detail="No tienes permiso para realizar esta acción (No eres el creador del ticket).")
    
    # Serializar la información en JSON
    solicitud_data = {
        "user_id": user_id,
        "user_response_id": None,
        "detalles": close_info.model_dump() if close_info else {}  # Convertir la info adicional en JSON
    }
    solicitud_json = json.dumps(solicitud_data)

    # Crear la nueva solicitud de cierre
    nueva_solicitud = Solicitud(
        ticket_id=ticket_id,
        description=solicitud_json,  # Almacenar la info en el campo description
        type="cierre",
        status="pendiente"
    )
    
    db.add(nueva_solicitud)
    ticket.state = "pendiente a revision"
    db.commit()

    return TicketSolicitudInfo(
        detail="Solicitud de cierre enviada correctamente. Sera notificado con la respuesta.",
        id_solicitud=nueva_solicitud.id
    )

"""

TODO: A la espera de tomar una decision sobre que hacer con estos endpoints

@ticket_router.get("/seguimiento", response_model=List[TicketData])
async def get_my_tickets(request: Request, db: Session = Depends(get_db), dependencies=Depends(bearer_scheme)):
    ""
    Obtiene todos los tickets creados por el usuario autenticado.
    
    Parámetros:.
    - db: Sesión de la base de datos. (Dependencia)
    
    Retorna:
    - Una lista de tickets creados por el usuario autenticado.

    ""
    # Extraer el ID del usuario autenticado desde el token
    user_info = request.state.user  
    user_id = user_info.get("sub")  
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Problema con la autenticacion de usuario.")
    
    # Consultar los tickets creados por el usuario autenticado
    tickets = db.query(Ticket).filter(Ticket.created_by == user_id).all()
    
    if not tickets:
        raise HTTPException(status_code=404, detail="No has creado ningún ticket.")
    
    # Devolver los tickets con los nombres completos
    return [
        TicketData(
            id=ticket.id,
            description=ticket.description,
            state=ticket.state,
            priority=ticket.priority,
            machine_serial=ticket.machine.serial,
            created_by=f"{db.query(User).filter(User.id == ticket.created_by).first().first_name} {db.query(User).filter(User.id == ticket.created_by).first().last_name}",  # Nombre completo del creador
            assigned_to=(f"{db.query(User).filter(User.id == ticket.assigned_to).first().first_name} {db.query(User).filter(User.id == ticket.assigned_to).first().last_name}" if ticket.assigned_to else None),  # Nombre completo del asignado si existe
            created_at=ticket.created_at,
            deadline=ticket.deadline
        )
        for ticket in tickets
    ]

@ticket_router.get("/my-tickets", response_model=List[TicketData])
async def get_assigned_tickets(request: Request, db: Session = Depends(get_db), dependencies=Depends(bearer_scheme)):
    ""
    Obtiene todos los tickets asignados al usuario autenticado, ordenados por prioridad
    y antigüedad.
    
    Orden:
    - Primero los de prioridad 'alta', luego 'media', luego 'baja', y por último los 'finalizados'.
    - Dentro de cada grupo, de los más antiguos a los más nuevos.
    ""
    # Extraer el ID del usuario autenticado desde el token
    user_info = request.state.user  
    user_id = user_info.get("sub")  
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Problema con la autenticacion de usuario.")
    
    # Consultar los tickets asignados al usuario autenticado y ordenarlos según estado, prioridad y fecha de creación
    
    tickets = db.query(Ticket).filter(Ticket.assigned_to == user_id).order_by(
        # Primero los tickets que no están finalizados, luego los finalizados
        case(
            (Ticket.state != 'finalizado', 1),
            else_=2  # Los tickets finalizados tienen menor prioridad en el orden
        ).asc(),
        # Luego dentro de los que no están finalizados, se ordenan por prioridad
        case(
            (Ticket.priority == 'alta', 1),
            (Ticket.priority == 'media', 2),
            (Ticket.priority == 'baja', 3),
            else_=4  # En caso de otros valores
        ).asc(),
        # Finalmente, ordenamos por la fecha de creación para cada grupo
        Ticket.created_at.asc()
    ).all()
    
    if not tickets:
        raise HTTPException(status_code=404, detail="No tienes tickets asignados.")
    
    # Devolver los tickets con los nombres completos
    return [
        TicketData(
            id=ticket.id,
            description=ticket.description,
            state=ticket.state,
            priority=ticket.priority,
            machine_serial=ticket.machine.serial,
            created_by=f"{db.query(User).filter(User.id == ticket.created_by).first().first_name} {db.query(User).filter(User.id == ticket.created_by).first().last_name}",
            assigned_to=f"{db.query(User).filter(User.id == ticket.assigned_to).first().first_name} {db.query(User).filter(User.id == ticket.assigned_to).first().last_name}" if ticket.assigned_to else None,
            created_at=ticket.created_at,
            deadline=ticket.deadline
        )
        for ticket in tickets
    ]"""