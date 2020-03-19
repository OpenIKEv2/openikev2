/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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
