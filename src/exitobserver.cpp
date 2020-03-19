/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "exitobserver.h"
#include <libopenikev2/threadcontroller.h>

ExitObserver::ExitObserver() {
    this->exit_semaphore = ThreadController::getSemaphore ( 0 );
    EventBus::getInstance().registerBusObserver ( *this, BusEvent::CORE_EVENT );
}


ExitObserver::~ExitObserver() {
}

void ExitObserver::notifyBusEvent ( const BusEvent & event ) {
    if ( event.type == BusEvent::CORE_EVENT ) {
        BusEventCore * busevent = ( BusEventCore* ) &event;
        if ( busevent->core_event_type == BusEventCore::ALL_SAS_CLOSED )
            this->exit_semaphore->post();
    }
}

void ExitObserver::waitForExitNotify() {
    this->exit_semaphore->wait();
}


