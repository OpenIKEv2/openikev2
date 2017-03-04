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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "configurerlibconfuse.h"
#include <libopenikev2/networkcontroller.h>
#include <libopenikev2/log.h>
#include <libopenikev2/exception.h>
#include <libopenikev2/utils.h>
#include <libopenikev2/ipseccontroller.h>
#include <libopenikev2/boolattribute.h>
#include <libopenikev2/stringattribute.h>
#include <libopenikev2/int32attribute.h>
#include <libopenikev2_impl/authenticatoropenike.h>

#ifdef EAP_SERVER_ENABLED
#include <libopenikev2_impl/eapservermd5.h>
#include <libopenikev2_impl/eapserverfrm.h>
#include <libopenikev2_impl/eapserverradius.h>
#endif

#ifdef EAP_CLIENT_ENABLED
#include <libopenikev2_impl/eapclientmd5.h>
#include <libopenikev2_impl/eapclientfrm.h>
#include <libopenikev2_impl/eapclienttls.h>
#endif

#include <libopenikev2_impl/ipaddressopenike.h>
#include <libopenikev2_impl/idtemplateexactmatch.h>
#include <libopenikev2_impl/idtemplateany.h>
#include <libopenikev2_impl/idtemplatedomainname.h>

#include <libopenikev2_impl/facade.h>
#include <libopenikev2_impl/utilsimpl.h>

ConfigurerLibConfuse::ConfigurerLibConfuse( string filename, LogImplOpenIKE& log ) {
    this->filename = filename;
    string vendor_id = "openikev2-" + UtilsImpl::charToString( OPENIKE_VERSION );

    // GENERAL SECTION FORMAT
    cfg_opt_t general_format[] = {
        CFG_INT( "max_ike_negotiation_time", 30, CFGF_NONE ),
        CFG_INT( "cookies_lifetime", 20, CFGF_NONE ),
        CFG_INT( "cookies_threshold", 5, CFGF_NONE ),
        CFG_STR( "vendor_id", ( char* ) vendor_id.c_str(), CFGF_NONE ),
#ifdef EAP_SERVER_ENABLED
        CFG_BOOL( "radvd_enabled", cfg_false, CFGF_NONE ),
	CFG_STR( "radvd_config_file", "/etc/radvd.conf", CFGF_NONE ),
#endif
        CFG_BOOL( "mobility", cfg_false, CFGF_NONE ),
        CFG_BOOL( "is_ha", cfg_false, CFGF_NONE ),
	CFG_STR( "home_address", "", CFGF_NONE ),

        CFG_END()
    };

    // LOG SECTION FORMAT
    cfg_opt_t log_format[] = {
        CFG_STR_LIST( "show_mask", "{all}", CFGF_NONE ),
        CFG_STR_LIST( "hide_mask", "{none}", CFGF_NONE ),
        CFG_BOOL( "show_extra_info", cfg_true, CFGF_NONE ),
        CFG_END()
    };

    // IKE PROPOSAL FORMAT
    cfg_opt_t ike_proposal_format[] = {
        CFG_STR_LIST( "encr", "{}", CFGF_NODEFAULT ),
        CFG_STR_LIST( "integ", "{}", CFGF_NODEFAULT ),
        CFG_STR_LIST( "prf", "{}", CFGF_NODEFAULT ),
        CFG_INT_LIST( "dh", "{}", CFGF_NODEFAULT ),
        CFG_END()
    };

    // ESP PROPOSAL FORMAT
    cfg_opt_t esp_proposal_format[] = {
        CFG_STR_LIST( "encr", "{}", CFGF_NODEFAULT ),
        CFG_STR_LIST( "integ", "{}", CFGF_NONE ),
        CFG_INT_LIST( "pfs_dh", "{}", CFGF_NONE ),
        CFG_STR( "use_esn", "omit", CFGF_NONE ),
        CFG_END()
    };

    // ESP PROPOSAL FORMAT
    cfg_opt_t ah_proposal_format[] = {
        CFG_STR_LIST( "integ", "{}", CFGF_NODEFAULT ),
        CFG_INT_LIST( "pfs_dh", "{}", CFGF_NONE ),
        CFG_STR( "use_esn", "omit", CFGF_NONE ),
        CFG_END()
    };

    // ID FORMAT
    cfg_opt_t id_format[] = {
        CFG_STR( "id_type", NULL, CFGF_NODEFAULT ),
        CFG_STR( "id", NULL, CFGF_NODEFAULT ),
        CFG_END()
    };

    // ADDRESS_CONFGURATION SERVER FORMAT
    cfg_opt_t address_config_server_format[] = {
        CFG_STR( "method", "none", CFGF_NONE ),
        CFG_STR( "autoconf_ipv6_prefix", NULL, CFGF_NONE ),
        CFG_STR( "protected_ipv4_subnet", NULL, CFGF_NONE ),
        CFG_STR( "protected_ipv6_subnet", NULL, CFGF_NONE ),
        CFG_STR( "fixed_ipv4_prefix", NULL, CFGF_NONE ),
        CFG_STR( "fixed_ipv6_prefix", NULL, CFGF_NONE ),
        CFG_STR( "dhcp_interface", "eth0", CFGF_NONE ),
        CFG_STR( "dhcp_server_ip", NULL, CFGF_NONE ),
        CFG_INT( "dhcp_timeout", 3, CFGF_NONE ),
        CFG_INT( "dhcp_retries", 3, CFGF_NONE ),
        CFG_END()
    };

    // ADDRESS_CONFGURATION CLIENT FORMAT
    cfg_opt_t address_config_client_format[] = {
        CFG_STR( "request_address", "none", CFGF_NONE ),
        CFG_STR( "request_ipv6_suffix", NULL, CFGF_NONE ),
        CFG_END()
    };

    // ADDRESS_CONFIGURATION FORMAT
    cfg_opt_t address_config_format[] = {
        CFG_SEC( "server", address_config_server_format, CFGF_NONE ),
        CFG_SEC( "client", address_config_client_format, CFGF_NONE ),
        CFG_END()
    };

    // IKE SECTION FORMAT
    cfg_opt_t ike_format[] = {
        CFG_SEC( "proposal", ike_proposal_format, CFGF_NODEFAULT ),
        CFG_SEC( "my_id", id_format, CFGF_NODEFAULT ),
        CFG_SEC( "peer_id", id_format, CFGF_MULTI ),
        CFG_STR( "auth_generator", "", CFGF_NONE ),
        CFG_STR_LIST( "auth_verifiers", "{}", CFGF_NONE ),
        CFG_STR_LIST( "eap_clients", "{}", CFGF_NONE ),
        CFG_STR_LIST( "eap_servers", "{}", CFGF_NONE ),
        CFG_STR( "aaa_protocol", "", CFGF_NONE ),
        CFG_STR( "my_preshared_key", "", CFGF_NONE ),
        CFG_STR( "peer_preshared_key", "", CFGF_NODEFAULT ),
        CFG_STR( "eap_md5_user_db", "", CFGF_NONE ),
        CFG_STR( "eap_md5_password", "", CFGF_NONE ),
        CFG_STR( "eap_tls_ca_cert", "", CFGF_NONE ),
        CFG_STR( "eap_tls_client_cert", "", CFGF_NONE ),
        CFG_STR( "eap_tls_private_key", "", CFGF_NONE ),
        CFG_STR( "eap_tls_private_key_password", "", CFGF_NONE ),
        CFG_STR( "eap_frm_client_data", "", CFGF_NONE ),
        CFG_STR( "eap_frm_server_data", "", CFGF_NONE ),
        CFG_STR( "aaa_server_addr", "", CFGF_NONE ),
        CFG_INT( "aaa_server_port", 1812, CFGF_NONE ),
        CFG_STR( "aaa_server_secret", "", CFGF_NONE ),

        CFG_STR_LIST( "my_ca_certificates", "{}", CFGF_NONE ),
        CFG_STR_LIST( "my_certificates", "{}", CFGF_NONE ),
        CFG_STR_LIST( "cert_white_list", "{}", CFGF_NONE ),
        CFG_STR_LIST( "cert_black_list", "{}", CFGF_NONE ),
        CFG_STR_LIST( "peer_ca_certificates", "{}", CFGF_NONE ),

        CFG_BOOL( "use_uname", cfg_false, CFGF_NONE ),
        CFG_BOOL( "mobike_supported", cfg_false, CFGF_NONE ),
        CFG_INT( "reauth_time", 0, CFGF_NONE ),
        CFG_BOOL( "send_cert_payload", cfg_true, CFGF_NONE ),
        CFG_BOOL( "send_cert_req_payload", cfg_true, CFGF_NONE ),
        CFG_BOOL( "hash_url_support", cfg_false, CFGF_NONE ),
        CFG_INT( "retransmition_time", 5, CFGF_NONE ),
        CFG_INT( "max_idle_time", 30, CFGF_NONE ),
        CFG_INT( "retransmition_factor", 2, CFGF_NONE ),
        CFG_INT( "rekey_time", 120, CFGF_NONE ),
        CFG_INT( "max_retries", 3, CFGF_NONE ),
        CFG_SEC( "address_configuration", address_config_format, CFGF_NONE ),
        CFG_END()
    };

    // IPSEC SECTION FORMAT
    cfg_opt_t ipsec_format[] = {
        CFG_SEC( "esp_proposal", esp_proposal_format, CFGF_NODEFAULT ),
        CFG_SEC( "ah_proposal", ah_proposal_format, CFGF_NODEFAULT ),
        CFG_INT( "max_allocations_soft", 0xFFFFFFF, CFGF_NONE ),
        CFG_INT( "max_allocations_hard", 0xFFFFFFF, CFGF_NONE ),
        CFG_INT( "lifetime_soft", 60, CFGF_NONE ),
        CFG_INT( "lifetime_hard", 65, CFGF_NONE ),
        CFG_INT( "max_bytes_soft", 0xFFFFFFF, CFGF_NONE ),
        CFG_INT( "max_bytes_hard", 0xFFFFFFF, CFGF_NONE ),
        CFG_END()
    };

    // PEER SECTION FORMAT
    cfg_opt_t peer_format[] = {
        CFG_STR_LIST( "peer_address", "{}", CFGF_NODEFAULT ),
        CFG_SEC( "ike", ike_format, CFGF_NODEFAULT ),
        CFG_SEC( "ipsec", ipsec_format, CFGF_NODEFAULT ),
        CFG_STR( "role", "any", CFGF_NONE ),

        CFG_END()
    };

    // POLICIES SECTION FORMAT
    cfg_opt_t policy_format[] = {
        CFG_STR( "src_selector", "", CFGF_NONE ),
        CFG_STR( "dst_selector", "", CFGF_NONE ),
        CFG_STR( "ip_proto", "any", CFGF_NONE ),
        CFG_INT( "src_port", 0, CFGF_NONE ),
        CFG_INT( "priority", 1000, CFGF_NONE ),
        CFG_INT( "dst_port", 0, CFGF_NONE ),
        CFG_INT( "icmp_code", 0, CFGF_NONE ),
        CFG_INT( "icmp_type", 0, CFGF_NONE ),
        CFG_BOOL( "autogen", cfg_false, CFGF_NONE ),
        CFG_BOOL( "sub", cfg_false, CFGF_NONE ),

        CFG_STR( "dir", "all", CFGF_NONE ),
        CFG_STR( "action", "allow", CFGF_NONE ),
        CFG_STR( "src_tunnel", "", CFGF_NONE ),
        CFG_STR( "dst_tunnel", "", CFGF_NONE ),
        CFG_STR( "ipsec_proto", "none", CFGF_NONE ),

        CFG_STR( "mode", "transport", CFGF_NONE ),
        CFG_END()
    };

    // POLICIES SECTION FORMAT
    cfg_opt_t policies_format[] = {
        CFG_SEC( "policy", policy_format, CFGF_MULTI ),
        CFG_BOOL( "flush_before", cfg_true, CFGF_NONE ),
        CFG_BOOL( "generate_allow_policies", cfg_true, CFGF_NONE ),
        CFG_END()
    };

    cfg_opt_t file_format[] = {
        CFG_SEC( "log", log_format, CFGF_NONE ),
        CFG_SEC( "general", general_format, CFGF_NODEFAULT ),
        CFG_SEC( "peer", peer_format, CFGF_MULTI ),
        CFG_SEC( "anonymous", peer_format, CFGF_NODEFAULT ),
        CFG_SEC( "policies", policies_format, CFGF_NODEFAULT ),
        CFG_END()
    };

    this->cfg = cfg_init( file_format, CFGF_NONE );

    int rv = cfg_parse( this->cfg, filename.c_str() );
    if ( rv != CFG_SUCCESS ) {
        if ( rv == CFG_FILE_ERROR )
            throw Exception( "Cannot read configuration file: " + filename );
        else
            throw Exception( "Parse error in configuration file: " + filename );
        return ;
    }

    Configuration::deleteConfiguration();

    Configuration::getInstance().setGeneralConfiguration( this->getGeneralConfiguration() );

    //cout << "\nParsing peer configuration.\n";
    for ( uint16_t i = 0; i < cfg_size( this->cfg, "peer" ); i++ ) {
        cfg_t* section = cfg_getnsec( this->cfg, "peer", i );
        Configuration::getInstance().addPeerConfiguration( this->getPeerConfiguration( section ) );
    }

    this->setLogConfiguration( log );
    //cout << "\nParsing polices.\n";
    this->parsePolicies();
    //cout << "\nEnd parsing.\n";

}

auto_ptr<GeneralConfiguration> ConfigurerLibConfuse::getGeneralConfiguration( ) {
    auto_ptr<GeneralConfiguration> general_configuration( new GeneralConfiguration() );

    cfg_t *current = cfg_getsec( this->cfg, "general" );
    if ( current == NULL )
        throw Exception( "Configuration MUST have a GENERAL section" );

    general_configuration->ike_max_halfopen_time = cfg_getint( current, "max_ike_negotiation_time" );
    general_configuration->cookie_lifetime = cfg_getint( current, "cookies_lifetime" );
    general_configuration->cookie_threshold = cfg_getint( current, "cookies_threshold" );

#ifdef EAP_SERVER_ENABLED
    bool radvd_enabled = cfg_getbool ( current, "radvd_enabled" );
    //cout << "radvd_enabled=" << radvd_enabled << endl;
    general_configuration->attributemap->addAttribute( "radvd_enabled", auto_ptr<Attribute> ( new BoolAttribute( radvd_enabled ) ) );
    string radvd_config_file = cfg_getstr ( current, "radvd_config_file" );
    //cout << "radvd_config_file=" << radvd_config_file << endl;
    general_configuration->attributemap->addAttribute( "radvd_config_file", auto_ptr<Attribute> ( new StringAttribute( radvd_config_file ) ) );
#endif

    bool mobility = cfg_getbool ( current, "mobility" );
    bool is_ha = cfg_getbool ( current, "is_ha" );
    //cout << "mobility_enabled=" << mobility << endl;
    general_configuration->attributemap->addAttribute( "mobility", auto_ptr<Attribute> ( new BoolAttribute( mobility ) ) );
    general_configuration->attributemap->addAttribute( "is_ha", auto_ptr<Attribute> ( new BoolAttribute( is_ha ) ) );
    string home_address = cfg_getstr ( current, "home_address" );
    //cout << "home_address=" << home_address << endl;
    general_configuration->attributemap->addAttribute( "home_address", auto_ptr<Attribute> ( new StringAttribute( home_address ) ) );
    //cout << "fin" << endl;
    string vendor_id = cfg_getstr( current, "vendor_id" );
    auto_ptr<ByteBuffer> byte_buffer( new ByteBuffer( vendor_id.size() ) );
    byte_buffer->writeBuffer( vendor_id.c_str(), vendor_id.size() );
    general_configuration->vendor_id = auto_ptr<ByteArray> ( byte_buffer );

    return general_configuration;
}

void ConfigurerLibConfuse::setLogConfiguration( LogImplOpenIKE& log ) {
    cfg_t * current = cfg_getsec( this->cfg, "log" );
    uint16_t mask = Log::LOG_NONE;


    for ( uint16_t i = 0; i < cfg_size( current, "show_mask" ); i++ ) {
        string name = cfg_getnstr( current, "show_mask", i );
        if ( name == "all" )
            mask |= Log::LOG_ALL;
        else if ( name == "none" )
            mask |= Log::LOG_NONE;
        else if ( name == "alarms" )
            mask |= Log::LOG_ALRM;
        else if ( name == "config" )
            mask |= Log::LOG_CONF;
        else if ( name == "crypto" )
            mask |= Log::LOG_CRYP;
        else if ( name == "ebus" )
            mask |= Log::LOG_EBUS;
        else if ( name == "exceptions" )
            mask |= Log::LOG_ERRO;
        else if ( name == "halfopen" )
            mask |= Log::LOG_HALF;
        else if ( name == "info" )
            mask |= Log::LOG_INFO;
        else if ( name == "dhcp" )
            mask |= Log::LOG_DHCP;
        else if ( name == "ipsec" )
            mask |= Log::LOG_IPSC;
        else if ( name == "messages" )
            mask |= Log::LOG_MESG;
        else if ( name == "policies" )
            mask |= Log::LOG_POLI;
        else if ( name == "transitions" )
            mask |= Log::LOG_STAT;
        else if ( name == "threads" )
            mask |= Log::LOG_THRD;
        else if ( name == "warnings" )
            mask |= Log::LOG_WARN;
    }

    for ( uint16_t i = 0; i < cfg_size( current, "hide_mask" ); i++ ) {
        string name = cfg_getnstr( current, "hide_mask", i );
        if ( name == "all" )
            mask &= ~Log::LOG_ALL;
        else if ( name == "none" )
            mask &= ~Log::LOG_NONE;
        else if ( name == "alarms" )
            mask &= ~Log::LOG_ALRM;
        else if ( name == "config" )
            mask &= ~Log::LOG_CONF;
        else if ( name == "crypto" )
            mask &= ~Log::LOG_CRYP;
        else if ( name == "ebus" )
            mask &= ~Log::LOG_EBUS;
        else if ( name == "exceptions" )
            mask &= ~Log::LOG_ERRO;
        else if ( name == "halfopen" )
            mask &= ~Log::LOG_HALF;
        else if ( name == "info" )
            mask &= ~Log::LOG_INFO;
        else if ( name == "dhcp" )
            mask &= ~Log::LOG_DHCP;
        else if ( name == "ipsec" )
            mask &= ~Log::LOG_IPSC;
        else if ( name == "messages" )
            mask &= ~Log::LOG_MESG;
        else if ( name == "policies" )
            mask &= ~Log::LOG_POLI;
        else if ( name == "transitions" )
            mask &= ~Log::LOG_STAT;
        else if ( name == "threads" )
            mask &= ~Log::LOG_THRD;
        else if ( name == "warnings" )
            mask &= ~Log::LOG_WARN;
    }

    log.setLogMask( mask );

    log.showExtraInfo( cfg_getbool( current, "show_extra_info" ) );;
}

ConfigurerLibConfuse::~ConfigurerLibConfuse() {
    cfg_free( this->cfg );
}


auto_ptr<Proposal> ConfigurerLibConfuse::getIkeProposal( cfg_t * current ) {
    if ( cfg_size( current, "encr" ) == 0 )
        throw Exception( "IKE proposal MUST have ENCR transforms" );
    if ( cfg_size( current, "integ" ) == 0 )
        throw Exception( "IKE proposal MUST have INTEG transforms" );
    if ( cfg_size( current, "prf" ) == 0 )
        throw Exception( "IKE proposal MUST have PRF transforms" );
    if ( cfg_size( current, "dh" ) == 0 )
        throw Exception( "IKE proposal MUST have DH transforms" );

    auto_ptr<Proposal> proposal( new Proposal( Enums::PROTO_IKE ) );

    for ( uint16_t i = 0; i < cfg_size( current, "encr" ); i++ ) {
        string name = cfg_getnstr( current, "encr", i );
        if ( name == "null" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_NULL ) ) );
        else if ( name == "des" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_DES ) ) );
        else if ( name == "3des" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_3DES ) ) );
        else if ( name == "rc5" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_RC5 ) ) );
        else if ( name == "idea" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_IDEA ) ) );
        else if ( name == "cast" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_CAST ) ) );
        else if ( name == "blowfish" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_BLOWFISH ) ) );
        else if ( name == "aes128" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 128 ) ) );
        else if ( name == "aes192" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 192 ) ) );
        else if ( name == "aes256" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 256 ) ) );
        else {
            throw Exception( "Unknown IKE ENCR transform: " + name );
        }
    }

    for ( uint16_t i = 0; i < cfg_size( current, "integ" ); i++ ) {
        string name = cfg_getnstr( current, "integ", i );
        if ( name == "none" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_NONE ) ) );
        else if ( name == "hmac_md5" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_HMAC_MD5_96 ) ) );
        else if ( name == "hmac_sha1" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_HMAC_SHA1_96 ) ) );
        else if ( name == "des_mac" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_DES_MAC ) ) );
        else if ( name == "kpdk_md5" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_KPDK_MD5 ) ) );
        else if ( name == "aes_xcbc" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_AES_XCBC_96 ) ) );
        else {
            throw Exception( "Unknown IKE INTEG transform: " + name );
        }
    }

    for ( uint16_t i = 0; i < cfg_size( current, "prf" ); i++ ) {
        string name = cfg_getnstr( current, "prf", i );
        if ( name == "md5" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::PRF, Enums::PRF_HMAC_MD5 ) ) );
        else if ( name == "sha1" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::PRF, Enums::PRF_HMAC_SHA1 ) ) );
        else if ( name == "tiger" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::PRF, Enums::PRF_HMAC_TIGER ) ) );
        else if ( name == "aes128" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::PRF, Enums::PRF_AES128_CBC ) ) );
        else {
            throw Exception( "Unknown IKE PRF transform: " + name );
        }
    }

    for ( uint16_t i = 0; i < cfg_size( current, "dh" ); i++ ) {
        uint16_t group = cfg_getnint( current, "dh", i );
        switch ( group ) {
            case 1:
            case 2:
            case 5:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::D_H, group ) ) );
                break;
            default:
                throw Exception( "Unknown IKE DH transform: " + intToString( group ) );
        }
    }

    return proposal;
}

auto_ptr<IkeSaConfiguration> ConfigurerLibConfuse::getIkeSaConfiguration( cfg_t * current ) {
    // Gets the mandatory proposal sub section
    cfg_t * sec_proposal = cfg_getsec( current, "proposal" );
    if ( sec_proposal == NULL )
        throw Exception( "IKE section must have a PROPOSAL section" );
    auto_ptr<IkeSaConfiguration> ike_sa_configuration( new IkeSaConfiguration( this->getIkeProposal( sec_proposal ) ) );

    // Gets the mandatory ID subsection
    cfg_t* sec_my_id = cfg_getsec( current, "my_id" );
    if ( sec_my_id == NULL )
        throw Exception( "IKE section must have a MY_ID section" );

    ike_sa_configuration->my_id = this->getId( sec_my_id );

    for ( uint16_t i = 0; i < cfg_size( current, "peer_id" ); i++ ) {
        cfg_t* allowed_id_sec = cfg_getnsec( current, "peer_id", i );
        ike_sa_configuration->addAllowedId( this->getIdTemplate( allowed_id_sec ) );
    }

    // Read authentication method
    string auth_generator_str = cfg_getstr( current, "auth_generator" );

    // Authenticator
    auto_ptr<AuthenticatorOpenIKE> authenticator( new AuthenticatorOpenIKE( ) );

    // If authentication method is PSK
    if ( auth_generator_str == "psk" ) {
        auto_ptr<AuthGeneratorPsk> auth_generator_psk = this->getAuthGeneratorPsk( current );
        authenticator->setAuthGenerator( auto_ptr<AuthGenerator> ( auth_generator_psk ) );
    }
    else if ( auth_generator_str == "cert" ) {
        auto_ptr<AuthGeneratorCert> auth_generator_cert = this->getAuthGeneratorCert( current );
        authenticator->setAuthGenerator( auto_ptr<AuthGenerator> ( auth_generator_cert ) );
    }
    else if ( auth_generator_str == "btns" ) {
        authenticator->setAuthGenerator( auto_ptr<AuthGenerator> ( new AuthGeneratorBtns() ) );
    }
    else {
        throw Exception( "Authentication generator not supported: <" + auth_generator_str + ">" );
    }

    // Read peer authentication method
    for ( uint16_t i = 0; i < cfg_size( current, "auth_verifiers" ); i++ ) {
        string auth_verifier_str = cfg_getnstr( current, "auth_verifiers", i );
        if ( auth_verifier_str == "psk" ) {
            auto_ptr<AuthVerifierPsk> auth_verifier_psk = this->getAuthVerifierPsk( current );
            authenticator->registerAuthVerifier( auto_ptr<AuthVerifier> ( auth_verifier_psk ) );
        }
        else if ( auth_verifier_str == "cert" ) {
            auto_ptr<AuthVerifierCert> auth_verifier_cert = this->getAuthVerifierCert( current );
            authenticator->registerAuthVerifier( auto_ptr<AuthVerifier> ( auth_verifier_cert ) );
        }
        else if ( auth_verifier_str == "btns" ) {
            authenticator->registerAuthVerifier( auto_ptr<AuthVerifier> ( new AuthVerifierBtns() ) );
        }

        else {
            throw Exception( "Authentication verifier not supported: <" + auth_verifier_str + ">" );
        }
    }

#ifdef EAP_CLIENT_ENABLED

    // Read Eap authentication method
    for ( uint16_t i = 0; i < cfg_size( current, "eap_clients" ); i++ ) {
        string eap_client_str = cfg_getnstr( current, "eap_clients", i );
        if ( eap_client_str == "eap_md5" ) {
            string eap_md5_password = cfg_getstr( current, "eap_md5_password" );
            authenticator->registerEapClient( auto_ptr<EapClient> ( new EapClientMd5( eap_md5_password ) ) );
        }
        else if ( eap_client_str == "eap_tls" ) {
            string eap_tls_ca_cert = cfg_getstr( current, "eap_tls_ca_cert" );
            string eap_tls_client_cert = cfg_getstr( current, "eap_tls_client_cert" );
            string eap_tls_private_key = cfg_getstr( current, "eap_tls_private_key" );
            string eap_tls_private_key_password = cfg_getstr( current, "eap_tls_private_key_password" );

            authenticator->registerEapClient( auto_ptr<EapClient> ( new EapClientTls( eap_tls_ca_cert, eap_tls_client_cert, eap_tls_private_key, eap_tls_private_key_password ) ) );
        }
        else if ( eap_client_str == "eap_frm" ) {
            // EAP_FRM
    	    string eap_frm_client_data = cfg_getstr( current, "eap_frm_client_data" );

            authenticator->registerEapClient( auto_ptr<EapClient> ( new EapClientFrm( eap_frm_client_data ) ) );
        }
        else //if ( eap_client_str != "" )
            throw Exception( "Unknown EAP client method: " + eap_client_str );
    }
#endif

    // Create the EAP server

#ifdef EAP_SERVER_ENABLED


    // Read AAA protocol
        string aaa_protocol = cfg_getstr( current, "aaa_protocol" );
        if ( aaa_protocol == "radius" ) {
            ike_sa_configuration->aaa_server_addr = cfg_getstr( current, "aaa_server_addr" );
            ike_sa_configuration->aaa_server_port = cfg_getint( current, "aaa_server_port" );
            ike_sa_configuration->aaa_server_secret = cfg_getstr( current, "aaa_server_secret" );

        }
        else if ( aaa_protocol != "" )
            throw Exception( "Unknown AAA protocol: " + aaa_protocol );


    // Read Eap authentication method
    for ( uint16_t i = 0; i < cfg_size( current, "eap_servers" ); i++ ) {

        string eap_server_str = cfg_getnstr( current, "eap_servers", i );
        if ( eap_server_str == "eap_md5" ) {
            string eap_md5_user_db = cfg_getstr( current, "eap_md5_user_db" );
            authenticator->registerEapServer( auto_ptr<EapServer> ( new EapServerMd5( eap_md5_user_db ) ) );
        }
        else if ( eap_server_str == "eap_radius" ) {

            authenticator->registerEapServer( auto_ptr<EapServer> ( new EapServerRadius( ike_sa_configuration->aaa_server_addr, ike_sa_configuration->aaa_server_port, ike_sa_configuration->aaa_server_secret ) ) );
        }
        else if ( eap_server_str == "eap_frm" ) {
            // EAP_FRM
	        //string eap_frm_server_data = cfg_getstr( current, "eap_frm_server_data" );

	        authenticator->registerEapServer( auto_ptr<EapServer> ( new EapServerFrm( ike_sa_configuration->aaa_server_addr , ike_sa_configuration->aaa_server_port , ike_sa_configuration->aaa_server_secret ) ) );
        }
        else if ( eap_server_str != "" )
            throw Exception( "Unknown EAP server method: " + eap_server_str );
    }







#endif
    ike_sa_configuration->retransmition_time = cfg_getint( current, "retransmition_time" );
    ike_sa_configuration->max_idle_time = cfg_getint( current, "max_idle_time" );
    ike_sa_configuration->retransmition_factor = cfg_getint( current, "retransmition_factor" );

    ike_sa_configuration->rekey_time = cfg_getint( current, "rekey_time" );
    ike_sa_configuration->ike_max_exchange_retransmitions = cfg_getint( current, "max_retries" );

    ike_sa_configuration->attributemap->addAttribute( "use_uname", auto_ptr<Attribute> ( new BoolAttribute( cfg_getbool( current, "use_uname" ) ) ) );

    ike_sa_configuration->attributemap->addAttribute( "mobike_supported", auto_ptr<Attribute> ( new BoolAttribute( cfg_getbool( current, "mobike_supported" ) ) ) );

    if ( cfg_getint( current, "reauth_time" ) != 0 ) {
        auto_ptr<Attribute> attribute( new Int32Attribute( cfg_getint( current, "reauth_time" ) ) );
        ike_sa_configuration->attributemap->addAttribute( "reauth_time", attribute );
    }


    ike_sa_configuration->authenticator = authenticator;

    // gets the server and client subsections (they have default values, so thet always exist)
    cfg_t* sec_iras = cfg_getsec( cfg_getsec( current, "address_configuration" ), "server" );
    cfg_t* sec_irac = cfg_getsec( cfg_getsec( current, "address_configuration" ), "client" );

    auto_ptr<StringAttribute> attribute( new StringAttribute( cfg_getstr( sec_irac, "request_address" ) ) );

    if ( attribute->value != "none"  && attribute->value != "ipv4" && attribute->value != "ipv6" && attribute->value != "autoconf")
        throw Exception( "Invalid request address family: <" + attribute->value + ">" );

    ike_sa_configuration->attributemap->addAttribute( "request_address", auto_ptr<Attribute> ( attribute ) );

    if ( cfg_getstr( sec_irac, "request_ipv6_suffix" ) != NULL && cfg_getbool( sec_irac, "request_address" ) ) {
        auto_ptr<NetworkPrefix> prefix = Facade::getNetworkPrefix( cfg_getstr( sec_irac, "request_ipv6_suffix" ) );
        ike_sa_configuration->attributemap->addAttribute( "request_ipv6_suffix", auto_ptr<Attribute> ( prefix ) );
    }

    string method = cfg_getstr( sec_iras, "method" );

    if ( method == "none" ) {
        ike_sa_configuration->attributemap->addAttribute( "configuration_method", auto_ptr<Attribute> ( new StringAttribute( "none" ) ) );
    }
    else {
        bool mandatory = false;
        if ( cfg_getstr( sec_iras, "protected_ipv4_subnet" ) != NULL ) {
            auto_ptr<NetworkPrefix> prefix = Facade::getNetworkPrefix( cfg_getstr( sec_iras, "protected_ipv4_subnet" ) );
            ike_sa_configuration->attributemap->addAttribute( "protected_ipv4_subnet", auto_ptr<Attribute> ( prefix ) );
            mandatory = true;
        }
        if ( cfg_getstr( sec_iras, "protected_ipv6_subnet" ) != NULL ) {
            auto_ptr<NetworkPrefix> prefix = Facade::getNetworkPrefix( cfg_getstr( sec_iras, "protected_ipv6_subnet" ) );
            ike_sa_configuration->attributemap->addAttribute( "protected_ipv6_subnet", auto_ptr<Attribute> ( prefix ) );
            mandatory = true;
        }

        if ( !mandatory )
            throw Exception( "Protected subnet (IPv4 or IPv6) section must exist" );

        if ( method == "fixed" ) {
            ike_sa_configuration->attributemap->addAttribute( "configuration_method", auto_ptr<Attribute> ( new StringAttribute( "fixed" ) ) );

            mandatory = false;
            if ( cfg_getstr( sec_iras, "fixed_ipv4_prefix" ) != NULL ) {
                auto_ptr<NetworkPrefix> prefix = Facade::getNetworkPrefix( cfg_getstr( sec_iras, "fixed_ipv4_prefix" ) );
                ike_sa_configuration->attributemap->addAttribute( "fixed_ipv4_prefix", auto_ptr<Attribute> ( prefix ) );
                mandatory = true;
            }
            if ( cfg_getstr( sec_iras, "fixed_ipv6_prefix" ) != NULL ) {
                auto_ptr<NetworkPrefix> prefix = Facade::getNetworkPrefix( cfg_getstr( sec_iras, "fixed_ipv6_prefix" ) );
                ike_sa_configuration->attributemap->addAttribute( "fixed_ipv6_prefix", auto_ptr<Attribute> ( prefix ) );
                mandatory = true;
            }

            if ( !mandatory )
                throw Exception( "Fixed prefix (IPv4 or IPv6) section must exist when method=fixed" );
        }
        else if ( method == "autoconf" ) {

            ike_sa_configuration->attributemap->addAttribute( "configuration_method", auto_ptr<Attribute> ( new StringAttribute( "autoconf" ) ) );

            mandatory = false;

            if ( cfg_getstr( sec_iras, "autoconf_ipv6_prefix" ) != NULL ) {
                auto_ptr<NetworkPrefix> prefix = Facade::getNetworkPrefix( cfg_getstr( sec_iras, "autoconf_ipv6_prefix" ) );
                ike_sa_configuration->attributemap->addAttribute( "autoconf_ipv6_prefix", auto_ptr<Attribute> ( prefix ) );
                mandatory = true;
            }
            else mandatory = false;

            if ( !mandatory )
                throw Exception( "Autoconf prefix (IPv6) section must exist when method=autoconf" );
        }
        else if ( method == "dhcp" ) {
            ike_sa_configuration->attributemap->addAttribute( "configuration_method", auto_ptr<Attribute> ( new StringAttribute( "dhcp" ) ) );

            // Duda hacer copia o no
            uint8_t* dhcp_interface = ( uint8_t* ) cfg_getstr( sec_iras, "dhcp_interface" );
            if ( dhcp_interface == NULL )
                throw Exception( "No interface defined in dhcp configuration." );

            ike_sa_configuration->attributemap->addAttribute( "dhcp_interface", auto_ptr<Attribute> ( new StringAttribute(( const char * ) dhcp_interface ) ) );
            delete[] dhcp_interface;

            uint8_t* address = ( uint8_t* ) cfg_getstr( sec_iras, "dhcp_server_ip" );
            if ( address != NULL ) {
                auto_ptr<IpAddress> ipaddress( new IpAddressOpenIKE(( const char* ) address ) );
                delete[] address;
                ike_sa_configuration->attributemap->addAttribute( "dhcp_server_ip", auto_ptr<Attribute> ( ipaddress ) );
            }
            else
                throw Exception( "No DHCP server ip defined in dhcp configuration." );

            ike_sa_configuration->attributemap->addAttribute( "dhcp_timeout", auto_ptr<Attribute> ( new Int32Attribute( cfg_getint( sec_iras, "dhcp_timeout" ) ) ) );
            ike_sa_configuration->attributemap->addAttribute( "dhcp_retries", auto_ptr<Attribute> ( new Int32Attribute( cfg_getint( sec_iras, "dhcp_retries" ) ) ) );
        }
        else
            Exception( "Unknown Address Configuration Method: [" + method + "]" );
    }

    return ike_sa_configuration;
}

auto_ptr<ID> ConfigurerLibConfuse::getId( cfg_t * current ) {
    auto_ptr<ID> id;

    char *id_type_char = cfg_getstr( current, "id_type" );
    string id_type_str = id_type_char;
    if ( id_type_char == NULL )
        throw Exception( "ID section MUST have an ID_TYPE attribute" );

    char *id_value_char = cfg_getstr( current, "id" );
    if ( id_value_char == NULL )
        throw Exception( "ID section MUST have an ID attribute" );

    if ( id_type_str == "fqdn" )
        id.reset( new ID( Enums::ID_FQDN, id_value_char ) );
    else if ( id_type_str == "rfc822" )
        id.reset( new ID( Enums::ID_RFC822_ADDR, id_value_char ) );
    else if ( id_type_str == "ipaddr" ) {
        auto_ptr<IpAddress> ip_addr( new IpAddressOpenIKE(( id_value_char ) ) );
        id.reset( new ID( *ip_addr ) );
    }
    else if ( id_type_str == "der_asn1_dn" ) {
        auto_ptr<CertificateX509> certificate( new CertificateX509( id_value_char, "" ) );
        id.reset( new ID( Enums::ID_DER_ASN1_DN, certificate->getDerSubjectName() ) );

    }
    else
        throw Exception( "Unknown ID type: " + id_type_str );

    return id;
}

auto_ptr<IdTemplate> ConfigurerLibConfuse::getIdTemplate( cfg_t * current ) {
    auto_ptr<IdTemplate> id;

    char *id_type_char = cfg_getstr( current, "id_type" );
    if ( id_type_char == NULL )
        throw Exception( "ID section MUST have an ID_TYPE attribute" );

    char *id_value_char = cfg_getstr( current, "id" );
    if ( id_value_char == NULL )
        throw Exception( "ID section MUST have an ID attribute" );

    string id_type_str = id_type_char;
    string id_value_str = id_value_char;

    if ( id_type_str == "domain_name" ) {
        id.reset( new IdTemplateDomainName( id_value_char ) );
    }
    else if ( id_type_str == "any" ) {
        id.reset( new IdTemplateAny( ) );
    }
    else if ( id_value_str == "any" ) {
        auto_ptr<ID> temp = this->getId( current );
        id.reset( new IdTemplateAny( temp->id_type ) );
    }
    else
        id.reset( new IdTemplateExactMatch( this->getId( current ) ) );

    return id;
}

auto_ptr<ChildSaConfiguration> ConfigurerLibConfuse::getChildSaConfiguration( cfg_t * current ) {
    auto_ptr<ChildSaConfiguration> child_sa_configuration;

    // Get the proposal sub section
    cfg_t* sec_esp_proposal = cfg_getsec( current, "esp_proposal" );
    cfg_t* sec_ah_proposal = cfg_getsec( current, "ah_proposal" );

    if ( sec_esp_proposal != NULL ) {
        child_sa_configuration.reset( new ChildSaConfiguration( this->getIpsecProposal( sec_esp_proposal, Enums::PROTO_ESP ) ) );
    }
    else if ( sec_ah_proposal != NULL ) {
        child_sa_configuration.reset( new ChildSaConfiguration( this->getIpsecProposal( sec_ah_proposal, Enums::PROTO_AH ) ) );
    }
    else
        Exception( "Missing IPsec proposal in the IPsec configuration section" );

    child_sa_configuration->lifetime_hard = cfg_getint( current, "lifetime_hard" );
    child_sa_configuration->lifetime_soft = cfg_getint( current, "lifetime_soft" );
    child_sa_configuration->max_bytes_hard = cfg_getint( current, "max_bytes_hard" );
    child_sa_configuration->max_bytes_soft = cfg_getint( current, "max_bytes_soft" );
    child_sa_configuration->max_allocations_hard = cfg_getint( current, "max_allocations_hard" );
    child_sa_configuration->max_allocations_soft = cfg_getint( current, "max_allocations_soft" );

    return child_sa_configuration;
}

auto_ptr<Proposal> ConfigurerLibConfuse::getIpsecProposal( cfg_t * current, Enums::PROTOCOL_ID proto ) {
    if ( proto == Enums::PROTO_ESP && ( cfg_size( current, "encr" ) == 0 ) )
        throw Exception( "IPSEC ESP proposal MUST have ENCR transforms" );

    if ( proto == Enums::PROTO_AH && cfg_size( current, "integ" ) == 0 )
        throw Exception( "IPSEC AH proposal MUST have INTEG transforms" );

    auto_ptr<Proposal> proposal( new Proposal( proto ) );

    if ( proto == Enums::PROTO_ESP ) {
        for ( uint16_t i = 0; i < cfg_size( current, "encr" ); i++ ) {
            string name = cfg_getnstr( current, "encr", i );
            if ( name == "null" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_NULL ) ) );
            else if ( name == "des" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_DES ) ) );
            else if ( name == "3des" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_3DES ) ) );
            else if ( name == "rc5" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_RC5 ) ) );
            else if ( name == "idea" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_IDEA ) ) );
            else if ( name == "cast" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_CAST ) ) );
            else if ( name == "blowfish" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_BLOWFISH ) ) );
            else if ( name == "aes128" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 128 ) ) );
            else if ( name == "aes192" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 192 ) ) );
            else if ( name == "aes256" )
                proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 256 ) ) );
            else {
                throw Exception( "Unknown IPSEC ENCR transform: " + name );
            }
        }
    }

    for ( uint16_t i = 0; i < cfg_size( current, "integ" ); i++ ) {
        string name = cfg_getnstr( current, "integ", i );
        if ( name == "none" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_NONE ) ) );
        else if ( name == "hmac_md5" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_HMAC_MD5_96 ) ) );
        else if ( name == "hmac_sha1" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_HMAC_SHA1_96 ) ) );
        else if ( name == "des_mac" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_DES_MAC ) ) );
        else if ( name == "kpdk_md5" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_KPDK_MD5 ) ) );
        else if ( name == "aes_xcbc" )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_AES_XCBC_96 ) ) );
        else {
            throw Exception( "Unknown IPSEC INTEG transform: " + name );
        }
    }

    for ( uint16_t i = 0; i < cfg_size( current, "pfs_dh" ); i++ ) {
        uint16_t group = cfg_getnint( current, "pfs_dh", i );
        if ( group == 0 )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::D_H, Enums::DH_GROUP_1 ) ) );
        else if ( group == 1 )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::D_H, Enums::DH_GROUP_1 ) ) );
        else if ( group == 2 )
            proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::D_H, Enums::DH_GROUP_2 ) ) );
        else {
            throw Exception( "Unknown IPSEC DH transform: " + intToString( group ) );
        }
    }

    string use_esn = cfg_getstr( current, "use_esn" );
    if ( use_esn == "yes" )
        proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ESN, Enums::ESN_YES ) ) );
    else if ( use_esn == "no" )
        proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ESN, Enums::ESN_NO ) ) );

    return proposal;
}

auto_ptr<PeerConfiguration> ConfigurerLibConfuse::getPeerConfiguration( cfg_t * current ) {
    auto_ptr<PeerConfiguration> peer_configuration( new PeerConfiguration() );

    for ( uint16_t i = 0; i < cfg_size( current, "peer_address" ); i++ ) {
        string network = cfg_getnstr( current, "peer_address", i );
        auto_ptr<NetworkPrefix> prefix = Facade::getNetworkPrefix( network );
        peer_configuration->addNetworkPrefix( prefix );
    }

    // Get the IKE section
    cfg_t* ike_section = cfg_getsec( current, "ike" );
    if ( ike_section != NULL )
        peer_configuration->setIkeSaConfiguration( this->getIkeSaConfiguration( ike_section ) );

    cfg_t* ipsec_section = cfg_getsec( current, "ipsec" );
    if ( ipsec_section != NULL )
        peer_configuration->setChildSaConfiguration( this->getChildSaConfiguration( ipsec_section ) );

    string role = cfg_getstr( current, "role" );
    if ( role == "any" )
        peer_configuration->setRole( Enums::ROLE_ANY );
    else if ( role == "initiator" )
        peer_configuration->setRole( Enums::ROLE_INITIATOR );
    else if ( role == "responder" )
        peer_configuration->setRole( Enums::ROLE_RESPONDER );
    else
        throw Exception( "Unknown role: " + role + ". In line " + intToString( current->line ) );

    return peer_configuration;
}

auto_ptr<AuthVerifierCert> ConfigurerLibConfuse::getAuthVerifierCert( cfg_t * current ) {
    auto_ptr<AuthVerifierCert> auth_verifier_cert( new AuthVerifierCert() );

    for ( uint16_t i = 0; i < cfg_size( current, "cert_white_list" ); i++ ) {
        string name = cfg_getnstr( current, "cert_white_list", i );
        string name_crt = name + ".crt";

        auto_ptr<CertificateX509> certificate( new CertificateX509( name_crt, "" ) );
        if ( !auth_verifier_cert->addWhiteListedCertificate( certificate ) )
            throw Exception( "Error adding white listed certificate" );
    }

    for ( uint16_t i = 0; i < cfg_size( current, "cert_black_list" ); i++ ) {
        string name = cfg_getnstr( current, "cert_black_list", i );
        string name_crt = name + ".crt";

        auto_ptr<CertificateX509> certificate( new CertificateX509( name_crt, "" ) );
        if ( !auth_verifier_cert->addBlackListedCertificate( certificate ) )
            throw Exception( "Error adding black listed certificate" );
    }

    for ( uint16_t i = 0; i < cfg_size( current, "peer_ca_certificates" ); i++ ) {
        string name = cfg_getnstr( current, "peer_ca_certificates", i );
        string name_crt = name + ".crt";

        auto_ptr<CertificateX509> certificate( new CertificateX509( name_crt, "" ) );

        if ( !auth_verifier_cert->addCaCertificate( certificate ) )
            throw Exception( "Error adding CA certificate" );
    }

    auth_verifier_cert->hash_url_support = cfg_getbool( current, "hash_url_support" );
    auth_verifier_cert->send_cert_req = cfg_getbool( current, "send_cert_req_payload" );

    return auth_verifier_cert;
}

auto_ptr<AuthGeneratorCert> ConfigurerLibConfuse::getAuthGeneratorCert( cfg_t * current ) {
    auto_ptr<AuthGeneratorCert> auth_generator_cert( new AuthGeneratorCert() );

    for ( uint16_t i = 0; i < cfg_size( current, "my_ca_certificates" ); i++ ) {
        string name = cfg_getnstr( current, "my_ca_certificates", i );
        string name_crt = name + ".crt";

        auto_ptr<CertificateX509> certificate( new CertificateX509( name_crt, "" ) );

        if ( !auth_generator_cert->addCaCertificate( certificate ) )
            throw Exception( "Error adding CA certificate" );
    }

    for ( uint16_t i = 0; i < cfg_size( current, "my_certificates" ); i++ ) {
        string full_name = cfg_getnstr( current, "my_certificates", i );
        string name = "";
        string url = "";

        string::size_type url_separator_pos = full_name.find( "@", 0 );

        if ( url_separator_pos == string::npos )
            name = full_name;
        else {
            name = full_name.substr( 0, url_separator_pos );
            url = full_name.substr( url_separator_pos + 1, full_name.size() - url_separator_pos - 1 );
        }

        string name_crt = name + ".crt";
        string name_key = name + ".key";

        auto_ptr<CertificateX509> certificate( new CertificateX509( name_crt, name_key ) );
        if ( !auth_generator_cert->addCertificate( certificate ) )
            throw Exception( "Error adding user certificates" );

        if ( url != "" ) {
            auto_ptr<CertificateX509HashUrl> hash_url_certificate( new CertificateX509HashUrl( url, name_key ) );
            if ( !( *certificate->getFingerPrint() == *hash_url_certificate->getFingerPrint() ) )
                throw Exception( "Error: Fingerprint of HASH & URL certificate doesn't match\n" + hash_url_certificate->toString() );

            if ( !auth_generator_cert->addCertificate( hash_url_certificate ) )
                throw Exception( "Error adding hash & url user certificates" );

        }

    }

    auth_generator_cert->send_cert = cfg_getbool( current, "send_cert_payload" );

    return auth_generator_cert;
}


void ConfigurerLibConfuse::parsePolicies( ) {
    cfg_t * current = cfg_getsec( this->cfg, "policies" );

    if ( current == NULL )
        return ;

    if ( cfg_getbool( current, "flush_before" ) ) {
        IpsecController::flushIpsecPolicies();
        IpsecController::flushIpsecSas();
    }

    if ( cfg_getbool( current, "generate_allow_policies" ) ) {
        // Add allow policies (IPv4)
        Facade::createIpsecPolicy( "0.0.0.0/0", 500, "0.0.0.0/0", 500, Enums::IP_PROTO_UDP, Enums::DIR_ALL, Enums::POLICY_ALLOW, 0 );

        // Add allow policies (IPv6)
        Facade::createIpsecPolicy( "::/0", 500, "::/0", 500, Enums::IP_PROTO_UDP, Enums::DIR_ALL, Enums::POLICY_ALLOW, 0 );
        //Facade::createIpsecPolicy( "::/0", 0, "::/0", 0, Enums::IP_PROTO_MH, Enums::DIR_ALL, Enums::POLICY_ALLOW, 1 );

        Facade::createIpsecPolicy( "::/0", "::/0", Enums::IP_PROTO_ICMPv6, 135, 0, Enums::DIR_ALL, Enums::POLICY_ALLOW, 10000 );
        Facade::createIpsecPolicy( "::/0", "::/0", Enums::IP_PROTO_ICMPv6, 136, 0, Enums::DIR_ALL, Enums::POLICY_ALLOW, 10000 );
    }

    for ( uint16_t i = 0; i < cfg_size( current, "policy" ); i++ ) {
        cfg_t* policy_sec = cfg_getnsec( current, "policy", i );
        string ip_proto = cfg_getstr( policy_sec, "ipsec_proto" );

        if ( ip_proto == "icmp" || ip_proto == "icmpv6" )
            Facade::createIpsecPolicy(
                cfg_getstr( policy_sec, "src_selector" ),
                cfg_getstr( policy_sec, "dst_selector" ),
                str_to_ip_proto( cfg_getstr( policy_sec, "ip_proto" ) ),
                cfg_getint( policy_sec, "icmp_type" ),
                cfg_getint( policy_sec, "icmp_code" ),
                str_to_direction( cfg_getstr( policy_sec, "dir" ) ),
                str_to_action( cfg_getstr( policy_sec, "action" ) ),
                cfg_getint( policy_sec, "priority" ),
                str_to_ipsec_proto( cfg_getstr( policy_sec, "ipsec_proto" ) ),
                str_to_ipsec_mode( cfg_getstr( policy_sec, "mode" ) ),
                cfg_getstr( policy_sec, "src_tunnel" ),
                cfg_getstr( policy_sec, "dst_tunnel" ),
		cfg_getbool( policy_sec, "autogen" ),
		cfg_getbool( policy_sec, "sub" )
                );
        else
            Facade::createIpsecPolicy(
                cfg_getstr( policy_sec, "src_selector" ),
                cfg_getint( policy_sec, "src_port" ),
                cfg_getstr( policy_sec, "dst_selector" ),
                cfg_getint( policy_sec, "dst_port" ),
                str_to_ip_proto( cfg_getstr( policy_sec, "ip_proto" ) ),
                str_to_direction( cfg_getstr( policy_sec, "dir" ) ),
                str_to_action( cfg_getstr( policy_sec, "action" ) ),
                cfg_getint( policy_sec, "priority" ),
                str_to_ipsec_proto( cfg_getstr( policy_sec, "ipsec_proto" ) ),
                str_to_ipsec_mode( cfg_getstr( policy_sec, "mode" ) ),
                cfg_getstr( policy_sec, "src_tunnel" ),
                cfg_getstr( policy_sec, "dst_tunnel" ),
		cfg_getbool( policy_sec, "autogen" ),
		cfg_getbool( policy_sec, "sub" )
            );
    }
}

uint16_t ConfigurerLibConfuse::str_to_ip_proto( string str ) {
    if ( str == "any" )
        return 0;
    else if ( str == "icmp" )
        return 1;
    else if ( str == "tcp" )
        return 6;
    else if ( str == "udp" )
        return 17;
    else if ( str == "icmpv6" )
        return 58;
    else
        return 0;
}

Enums::IPSEC_MODE ConfigurerLibConfuse::str_to_ipsec_mode( string mode ) {
    if ( mode == "transport" )
        return Enums::TRANSPORT_MODE;
    else if ( mode == "tunnel" )
        return Enums::TUNNEL_MODE;
    else
        throw Exception( "MODE = " + mode + " unknown" );
}

Enums::DIRECTION ConfigurerLibConfuse::str_to_direction( string dir ) {
    if ( dir == "in" )
        return Enums::DIR_IN;
    else if ( dir == "out" )
        return Enums::DIR_OUT;
    else if ( dir == "fwd" )
        return Enums::DIR_FWD;
    else if ( dir == "all" )
        return Enums::DIR_ALL;
    else
        throw Exception( "DIR = " + dir + " unknown" );
}

Enums::POLICY_ACTION ConfigurerLibConfuse::str_to_action( string dir ) {
    if ( dir == "allow" )
        return Enums::POLICY_ALLOW;
    else if ( dir == "block" )
        return Enums::POLICY_BLOCK;
    else
        throw Exception( "ACTION = " + dir + " unknown" );
}

Enums::PROTOCOL_ID ConfigurerLibConfuse::str_to_ipsec_proto( string str ) {
    if ( str == "esp" )
        return Enums::PROTO_ESP;
    else if ( str == "ah" )
        return Enums::PROTO_AH;
    else if ( str == "none" )
        return Enums::PROTO_NONE;
    else
        throw Exception( "PROTO = " + str + " unknown" );
}

auto_ptr< AuthGeneratorPsk > ConfigurerLibConfuse::getAuthGeneratorPsk( cfg_t * current ) {
    // Read PSK (if available)
    char* preshared_key_filename = cfg_getstr( current, "my_preshared_key" );
    FILE* stream = fopen( preshared_key_filename, "rb" );

    if ( stream == NULL )
        throw Exception( "Cannot read PSK file" );

    fseek( stream, 0, SEEK_END );
    uint16_t preshared_key_len = ftell( stream );
    uint8_t *preshared_key = new uint8_t [ preshared_key_len ];

    fseek( stream, 0, SEEK_SET );
    fread( preshared_key, 1, preshared_key_len, stream );
    fclose( stream );

    return auto_ptr<AuthGeneratorPsk> ( new AuthGeneratorPsk( auto_ptr<ByteArray> ( new ByteArray( preshared_key, preshared_key_len, 0, true ) ) ) );
}

auto_ptr< AuthVerifierPsk > ConfigurerLibConfuse::getAuthVerifierPsk( cfg_t * current ) {
    // Read PSK (if available)
    char* preshared_key_filename = cfg_getstr( current, "peer_preshared_key" );
    FILE* stream = fopen( preshared_key_filename, "rb" );

    if ( stream == NULL )
        throw Exception( "Cannot read PSK file" );

    fseek( stream, 0, SEEK_END );
    uint16_t preshared_key_len = ftell( stream );
    uint8_t *preshared_key = new uint8_t [ preshared_key_len ];

    fseek( stream, 0, SEEK_SET );
    fread( preshared_key, 1, preshared_key_len, stream );
    fclose( stream );

    return auto_ptr<AuthVerifierPsk> ( new AuthVerifierPsk( auto_ptr<ByteArray> ( new ByteArray( preshared_key, preshared_key_len, 0, true ) ) ) );
}



