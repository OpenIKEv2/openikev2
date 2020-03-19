/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef EXITOBSERVER_H
#define EXITOBSERVER_H

#include <libopenikev2/eventbus.h>
#include <libopenikev2/semaphore.h>
#include <libopenikev2/busobserver.h>
#include <libopenikev2/buseventcore.h>


using namespace openikev2;
/**
This class provides an observer to force exit main program after all the SAs have been closed
 @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
*/
class ExitObserver : public BusObserver {
    protected:
        auto_ptr<Semaphore> exit_semaphore;

    public:
        ExitObserver();
        void notifyBusEvent ( const BusEvent& event );
        void waitForExitNotify();
        ~ExitObserver();
};

#endif
