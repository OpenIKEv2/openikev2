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
#ifndef CONFIGURERLIBCONFUSE_H
#define CONFIGURERLIBCONFUSE_H

#include <confuse.h>
#include <libopenikev2/enums.h>
#include <libopenikev2/configuration.h>
#include <libopenikev2_impl/certificatex509.h>
#include <libopenikev2_impl/authgeneratorpsk.h>
#include <libopenikev2_impl/authverifierpsk.h>
#include <libopenikev2_impl/authgeneratorcert.h>
#include <libopenikev2_impl/authverifiercert.h>
#include <libopenikev2_impl/authgeneratorbtns.h>
#include <libopenikev2_impl/authverifierbtns.h>
#include <libopenikev2_impl/logimplopenike.h>

using namespace openikev2;

/**
    Parses a configuration file using the libconfuse library and updates the Configuration Singleton
    @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez
*/
class ConfigurerLibConfuse {
    protected:
        string filename;                    /**< Configuration file name */
        cfg_t *cfg;                         /**< Internal configuration representation */

        uint16_t str_to_ip_proto( string str );
        Enums::IPSEC_MODE str_to_ipsec_mode( string mode );
        Enums::DIRECTION str_to_direction( string dir );
        Enums::POLICY_ACTION str_to_action( string dir );
        Enums::PROTOCOL_ID str_to_ipsec_proto( string str );

        /**
         * Parses the general section
         * @return A new GeneralConfiguration object
         */
        auto_ptr<GeneralConfiguration> getGeneralConfiguration();

        /**
         * Parses an IKE proposal subsection
         * @param current Current context
         * @return A new Proposal object
         */
        auto_ptr<Proposal> getIkeProposal( cfg_t *current );

        /**
         * Parses an IPSEC proposal subsection
         * @param current Current context
         * @param proto IPsec protocol of the proposal
         * @return A new Proposal object
         */
        auto_ptr<Proposal> getIpsecProposal( cfg_t *current, Enums::PROTOCOL_ID proto );

        /**
         * Parses an ID subsection
         * @param current Current context
         * @return A new ID object
         */
        auto_ptr<ID> getId( cfg_t* current );

        /**
         * Parses an ID subsection
         * @param current Current context
         * @return A new ID object
         */
        auto_ptr<IdTemplate> getIdTemplate( cfg_t* current );

        /**
         * Parses an IKE configuration subsection
         * @param current Current context
         * @return A new IKE_Configuration object
         */
        auto_ptr<IkeSaConfiguration> getIkeSaConfiguration( cfg_t *current );

        /**
         * Parses an IPSEC configuration subsection
         * @param current Current context
         * @return A new IPSEC_Configuration object
         */
        auto_ptr<ChildSaConfiguration> getChildSaConfiguration( cfg_t* current );

        /**
         * Parses a Peer configuration subsection
         * @param current Current context
         * @return A new PeerConfiguration object
         */
        auto_ptr<PeerConfiguration> getPeerConfiguration( cfg_t* current );

        /**
         * Parses all the certificate parameters
         * @param current Current context
         * @return A new CertificateController_OpenIKE object
         */
        auto_ptr<AuthVerifierCert> getAuthVerifierCert( cfg_t* current );

        auto_ptr<AuthGeneratorCert> getAuthGeneratorCert( cfg_t* current );

        auto_ptr<AuthGeneratorPsk> getAuthGeneratorPsk(  cfg_t* current );

        auto_ptr<AuthVerifierPsk> getAuthVerifierPsk(  cfg_t* current );

        /**
         * Parses the log mask from configuration file and set it proppertly
         */
        void setLogConfiguration( LogImplOpenIKE& log);

        void parsePolicies();

    public:

        /**
         * Creates a new ConfigurerLibConfuse object, parses the indicated file and updates Configuration Singleton
         * @param filename Configuration file name
         */
        ConfigurerLibConfuse( string filename, LogImplOpenIKE& log);

        ~ConfigurerLibConfuse();

};

#endif
