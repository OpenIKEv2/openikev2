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
#ifndef IKESAINFO_H
#define IKESAINFO_H

#include <libopenikev2/ikesa.h>
#include <libopenikev2/ipaddress.h>

using namespace openikev2;

/**
 @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
*/
class IkeSaInfo {
    public:
        auto_ptr<IpAddress> my_addr;
        auto_ptr<IpAddress> peer_addr;
        uint64_t my_spi;
        uint64_t peer_spi;

    protected:
        IkeSaInfo();

    public:
        IkeSaInfo ( const IkeSa& ike_sa );
        static auto_ptr<IkeSaInfo> parse ( ByteBuffer& byte_buffer );
        void updateInfo ( const IkeSa& ike_sa );
        void getBinaryRepresentation ( ByteBuffer& byte_buffer ) const;
        ~IkeSaInfo();

};

#endif
