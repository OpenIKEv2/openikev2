/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "ikesainfo.h"
#include <libopenikev2_impl/ipaddressopenike.h>


IkeSaInfo::IkeSaInfo ( const IkeSa& ike_sa ) {
    this->updateInfo ( ike_sa );
}

IkeSaInfo::IkeSaInfo ( ) {
}

void IkeSaInfo::updateInfo ( const IkeSa & ike_sa ) {
    this->my_addr = ike_sa.my_addr->getIpAddress().clone();
    this->peer_addr = ike_sa.peer_addr->getIpAddress().clone();
    this->my_spi = ike_sa.my_spi;
    this->peer_spi = ike_sa.peer_spi;
}

IkeSaInfo::~IkeSaInfo() {
}

void IkeSaInfo::getBinaryRepresentation ( ByteBuffer & byte_buffer ) const {
    byte_buffer.writeInt8 ( this->my_addr->getFamily() );
    byte_buffer.writeInt8 ( this->my_addr->getAddressSize() );
    byte_buffer.writeByteArray ( *this->my_addr->getBytes() );
    byte_buffer.writeInt8 ( this->peer_addr->getFamily() );
    byte_buffer.writeInt8 ( this->peer_addr->getAddressSize() );
    byte_buffer.writeByteArray ( *this->peer_addr->getBytes() );
    byte_buffer.writeBuffer ( &this->my_spi, 8 );
    byte_buffer.writeBuffer ( &this->peer_spi, 8 );
}

auto_ptr< IkeSaInfo > IkeSaInfo::parse ( ByteBuffer & byte_buffer ) {
    auto_ptr<IkeSaInfo> result ( new IkeSaInfo() );

    Enums::ADDR_FAMILY my_family = ( Enums::ADDR_FAMILY ) byte_buffer.readInt8();
    uint8_t my_addr_size = byte_buffer.readInt8();
    result->my_addr.reset ( new IpAddressOpenIKE ( my_family, byte_buffer.readByteArray ( my_addr_size ) ) );

    Enums::ADDR_FAMILY peer_family = ( Enums::ADDR_FAMILY ) byte_buffer.readInt8();
    uint8_t peer_addr_size = byte_buffer.readInt8();
    result->peer_addr.reset ( new IpAddressOpenIKE ( peer_family, byte_buffer.readByteArray ( peer_addr_size ) ) );

    byte_buffer.readBuffer(8, &result->my_spi);
    byte_buffer.readBuffer(8, &result->peer_spi);

    return result;
}




