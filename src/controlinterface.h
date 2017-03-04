/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *                                                                         *
 *   This library is free software; you can redistribute it and/or         *
 *   modify it under the terms of the GNU Lesser General Public            *
 *   License as published by the Free Software Foundation; either          *
 *   version 2.1 of the License, or (at your option) any later version.    *
 *                                                                         *
 *   This library is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *
 *   Lesser General Public License for more details.                       *
 *                                                                         *
 *   You should have received a copy of the GNU Lesser General Public      *
 *   License along with this library; if not, write to the Free Software   *
 *   Foundation, Inc., 51 Franklin St, Fifth Floor,                        *
 *   Boston, MA  02110-1301  USA                                           *
 ***************************************************************************/
#ifndef CONTROLINTERFACE_H
#define CONTROLINTERFACE_H

#include <libopenikev2/eventbus.h>
#include <libopenikev2/busobserver.h>
#include <libopenikev2/buseventcore.h>
#include <libopenikev2_impl/threadposix.h>
#include <libopenikev2_impl/udpsocket.h>
#include <iostream>
#include <cstdlib>

#include "ikesainfo.h"

using namespace openikev2;
using namespace std;

/**
 This class provides a control interface for the openikev2 daemon
 @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
*/
class ControlInterface : public BusObserver, public ThreadPosix {
    protected:
        auto_ptr<UdpSocket> socket;
        map<uint64_t, IkeSaInfo*> ike_sa_info_collection;

    public:
        ControlInterface ( uint16_t listening_port );
        void run();
        virtual void notifyBusEvent ( const BusEvent& event );
        ~ControlInterface();

};

#endif
