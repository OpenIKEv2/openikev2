/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
 *   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <cstdlib>

#include <libopenikev2/bytebuffer.h>
#include <libopenikev2_impl/udpsocket.h>
#include <libopenikev2_impl/ipaddressopenike.h>

#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/log.h>
#include <libopenikev2_impl/threadcontrollerimplposix.h>
#include <libopenikev2_impl/logimplcolortext.h>
#include <libopenikev2_impl/cipheropenssl.h>
#include <libopenikev2_impl/utilsimpl.h>
#include "ikesainfo.h"
#include <unistd.h>

using namespace openikev2;

int main ( int argc, char *argv[] ) {
    if (argc < 2){
        cout << "Usage: " << argv[0] << " address" << endl;
        exit(1);
    }
    
    // Loads the controllers
    auto_ptr<ThreadControllerImplPosix> thread_controller_posix ( new ThreadControllerImplPosix() );
    ThreadController::setImplementation ( thread_controller_posix.get() );

    auto_ptr<LogImplOpenIKE> log_impl ( new LogImplColorText() );
    Log::setImplementation ( log_impl.get() );

    // Setup the basic log
    log_impl->setLogMask ( Log::LOG_NONE );
    log_impl->open ( "/dev/null" );

    SocketAddressPosix src (auto_ptr<IpAddress> (new IpAddressOpenIKE ( "0.0.0.0" ) ), 6000 );
    SocketAddressPosix dst (auto_ptr<IpAddress> (new IpAddressOpenIKE ( argv[1] ) ), 12345 );
    UdpSocket udp_socket;    
    udp_socket.bind( src );

    while ( true ) {
        try {
            auto_ptr<ByteBuffer> request ( new ByteBuffer ( 1 ) );
            request->writeInt8 ( 1 );
            udp_socket.send ( src, dst, *request );

            auto_ptr<SocketAddress> src2, dst2;
            auto_ptr<ByteArray> response = udp_socket.receive ( src2, dst2, 1000 );            
            system ( "clear" );

            ByteBuffer response_buffer ( *response );
            uint8_t rescode = response_buffer.readInt8();
            if ( rescode == 1 ) {
                uint16_t num_of_ikesas = response_buffer.readInt16();
                cout << "OpenIKEv2 running on: " << src2->toString() << endl;
                cout << "Number of active IKE_SAS: " << num_of_ikesas << endl;
                for ( uint16_t i=0; i< num_of_ikesas; i++ ) {		    
                    auto_ptr<IkeSaInfo> ike_sa_info = IkeSaInfo::parse ( response_buffer );

                    string result = UtilsImpl::getPaddedString ( ike_sa_info->my_addr->toString(), 50, true, ' ' ) + "  <====================================>  " + ike_sa_info->peer_addr->toString() + "\n";
                    result += UtilsImpl::getPaddedString ( Printable::toHexString ( &ike_sa_info->my_spi, 8 ), 50, true, ' ' ) + "                                          " + Printable::toHexString ( &ike_sa_info->peer_spi, 8 ) + "\n";

                    cout << result << endl;
                }
            }
            sleep ( 1 );
        }
        catch ( exception& ex ) {
            cout << "EXCEPCION: " << ex.what() << endl;
        }
    }

    return EXIT_SUCCESS;
}
