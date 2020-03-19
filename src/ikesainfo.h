/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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
