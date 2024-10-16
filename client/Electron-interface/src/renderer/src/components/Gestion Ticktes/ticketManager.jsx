import React, { useState } from 'react';
import TicketList from './TieckteList';
import RequestsManager from './RequestManager';
import { HiChevronDown } from 'react-icons/hi';

const TicketsManager = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState(null);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const handleSelectSection = (section) => {
    setActiveSection(section);
    setMenuOpen(false);
  };

  return (
    <div className="bg-white min-h-screen p-6 relative">
      <h1 className="text-3xl font-bold text-center text-gray-800 mb-6">Gestión de Tickets</h1>

      <div className="flex justify-center mb-4 relative">
        <button
          onClick={toggleMenu}
          className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-full shadow-lg hover:bg-blue-700 transition duration-300"
        >
          <span className="mr-2">Gestión de Tickets</span>
          <HiChevronDown />
        </button>

        {menuOpen && (
          <div className="absolute top-12 bg-white rounded-lg mt-2 w-56 z-10">
            <ul className="flex flex-col">
              <li>
                <button
                  onClick={() => handleSelectSection('list')}
                  className="w-full text-left px-4 py-2 hover:bg-blue-100 focus:outline-none"
                >
                  Lista de Tickets
                </button>
              </li>
              <li>
                <button
                  onClick={() => handleSelectSection('requests')}
                  className="w-full text-left px-4 py-2 hover:bg-blue-100 focus:outline-none"
                >
                  Gestión de Solicitudes
                </button>
              </li>
            </ul>
          </div>
        )}
      </div>

      {/* Mostrar componente según la sección activa */}
      {activeSection === 'list' && (
        
        
          <TicketList />
        
      )}

      {activeSection === 'requests' && (
        <div className="bg-white p-6 rounded-lg shadow-lg transition-transform transform hover:scale-105 duration-300 mt-4">
          <h2 className="text-2xl font-semibold mb-4 text-blue-600">Gestión de Solicitudes</h2>
          <RequestsManager />
        </div>
      )}
    </div>
  );
};

export default TicketsManager;
