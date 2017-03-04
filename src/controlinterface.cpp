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
#include "controlinterface.h"
#include <libopenikev2/networkcontroller.h>
#include <libopenikev2_impl/udpsocket.h>
#include <libopenikev2_impl/ipaddressopenike.h>
#include <libopenikev2/buseventikesa.h>



ControlInterface::ControlInterface ( uint16_t listening_port ) {
    this->socket.reset ( new UdpSocket ( ) );
    this->socket->bind( SocketAddressPosix(auto_ptr<IpAddress> (new IpAddressOpenIKE("0.0.0.0") ), 12345 ) );
    EventBus::getInstance().registerBusObserver ( *this, BusEvent::IKE_SA_EVENT );
}

ControlInterface::~ControlInterface() {
}

void ControlInterface::run() {
    while ( true ) {
        auto_ptr<SocketAddress> src, dst;

        while ( true ) {
            auto_ptr<ByteArray> request = this->socket->receive ( src, dst );
            ByteBuffer request_buffer ( *request );
            uint8_t reqcode = request_buffer.readInt8();
            if ( reqcode == 1 ) {
                ByteBuffer response ( 3000 );
                response.writeInt8 ( 1 );
                response.writeInt16 ( this->ike_sa_info_collection.size() );
                for ( map<uint64_t, IkeSaInfo*>::iterator it = this->ike_sa_info_collection.begin(); it != this->ike_sa_info_collection.end(); it++ )
                    it->second->getBinaryRepresentation ( response );
                this->socket->send ( *dst, *src, response );
            }
        }
    }
}

void ControlInterface::notifyBusEvent ( const BusEvent & event ) {
    if ( event.type == BusEvent::IKE_SA_EVENT ) {
        BusEventIkeSa * ike_sa_event = ( BusEventIkeSa* ) &event;

        if ( ike_sa_event->ike_sa_event_type == BusEventIkeSa::IKE_SA_CREATED ) {
            pair<uint64_t, IkeSaInfo*> new_pair ( ike_sa_event->ike_sa.my_spi, new IkeSaInfo ( ike_sa_event->ike_sa ) );
            this->ike_sa_info_collection.insert ( new_pair );
        }

        else if ( ike_sa_event->ike_sa_event_type == BusEventIkeSa::IKE_SA_ESTABLISHED ) {
            map<uint64_t, IkeSaInfo*>::iterator it = this->ike_sa_info_collection.find ( ike_sa_event->ike_sa.my_spi );
            if (it == this->ike_sa_info_collection.end()) {
                pair<uint64_t, IkeSaInfo*> new_pair ( ike_sa_event->ike_sa.my_spi, new IkeSaInfo ( ike_sa_event->ike_sa ) );
                this->ike_sa_info_collection.insert ( new_pair );
	    }

            it = this->ike_sa_info_collection.find ( ike_sa_event->ike_sa.my_spi );

	    assert ( it != this->ike_sa_info_collection.end() );
            it->second->updateInfo ( ike_sa_event->ike_sa );
        }

        else if ( ike_sa_event->ike_sa_event_type == BusEventIkeSa::IKE_SA_REKEYED ) {
            map<uint64_t, IkeSaInfo*>::iterator it = this->ike_sa_info_collection.find ( ike_sa_event->ike_sa.my_spi );
            assert ( it != this->ike_sa_info_collection.end() ); // Esto de vez en cuando falla (PEDRO)
            it->second->updateInfo ( ike_sa_event->ike_sa );
        }

        if ( ike_sa_event->ike_sa_event_type == BusEventIkeSa::IKE_SA_DELETED || ike_sa_event->ike_sa_event_type == BusEventIkeSa::IKE_SA_FAILED) {
            map<uint64_t, IkeSaInfo*>::iterator it = this->ike_sa_info_collection.find ( ike_sa_event->ike_sa.my_spi );
            if ( it == this->ike_sa_info_collection.end() )
                return;

            delete it->second;
            this->ike_sa_info_collection.erase ( it );
        }
    }
}




