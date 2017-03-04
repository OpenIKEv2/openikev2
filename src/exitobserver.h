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
