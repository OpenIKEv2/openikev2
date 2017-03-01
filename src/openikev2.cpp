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

#include <libopenikev2/ikesa.h>

#include "configurerlibconfuse.h"
#include <libopenikev2/boolattribute.h>

#include <iostream>
#include <cstdlib>
#include <libopenikev2/configuration.h>
#include <libopenikev2/alarmcontroller.h>
#include <libopenikev2_impl/alarmcontrollerimplopenike.h>

#include <libopenikev2/log.h>
#include <libopenikev2_impl/logimpltext.h>
#include <libopenikev2_impl/logimplcolortext.h>
#include <libopenikev2_impl/logimplhtml.h>

#include <libopenikev2/configuration.h>

#include <libopenikev2/ipseccontroller.h>
#include <libopenikev2_impl/ipseccontrollerimplpfkeyv2.h>
#include <libopenikev2_impl/ipseccontrollerimplxfrm.h>

#include <libopenikev2/threadcontroller.h>
#include <libopenikev2_impl/threadcontrollerimplposix.h>

#include <libopenikev2_impl/cryptocontrollerimplopenike.h>
#include <libopenikev2/cryptocontroller.h>

#include <libopenikev2/networkcontroller.h>
#include <libopenikev2_impl/networkcontrollerimplopenike.h>

#include <libopenikev2/aaacontroller.h>
#include <libopenikev2_impl/aaacontrollerimplradius.h>

#include <signal.h>

#include <libopenikev2/ikesacontroller.h>

#include <libopenikev2_impl/notifycontroller_auth_lifetime.h>
#include <libopenikev2_impl/notifycontroller_mobike_supported.h>
#include <libopenikev2_impl/notifycontroller_update_sa_addresses.h>

#include <libopenikev2_impl/utilsimpl.h>

#include <libopenikev2_impl/ikesacontrollerimplopenike.h>
#include "exitobserver.h"
#include "controlinterface.h"

#include <sys/time.h>

void finalice();
using namespace std;
using namespace openikev2;

auto_ptr<ThreadControllerImplPosix> thread_controller_posix;
auto_ptr<LogImplOpenIKE> log_impl_openike;
auto_ptr<AlarmControllerImplOpenIKE> alarm_controller;
auto_ptr<NetworkControllerImplOpenIKE> network_controller_openike;
auto_ptr<CryptoControllerImplOpenIKE> crypto_controller_openike;
auto_ptr<IpsecControllerImplOpenIKE> ipsec_controller;
auto_ptr<IkeSaControllerImplOpenIKE> ike_sa_controller_openike;
auto_ptr<AAAControllerImplRadius> aaa_controller_radius;



void termination_handler ( int signum ) {
    if ( ike_sa_controller_openike->isExiting() ) {
        Log::writeLockedMessage ( "OpenIKEv2", "Repeated termination signal received. Killing OpenIKEv2 daemon...", Log::LOG_INFO, true );
        finalice();
        exit ( 1 );
    }

    Log::writeLockedMessage ( "OpenIKEv2", "Termination signal received. Shutting down OpenIKEv2 daemon...", Log::LOG_INFO, true );
    ike_sa_controller_openike->exit();
    ipsec_controller->exit();
    network_controller_openike->exit();
}

int main ( int argc, char *argv[] ) {
    if ( geteuid() != 0 ) {
        fprintf ( stderr, "You must be root in order to execute openikev2. You are UID=%u, EUID=%u\n", getuid(), geteuid() );
        return 1;
    }


    try {
        // Get options
        bool foreground = false;
        string configuration_filename = "/etc/openikev2/openikev2.conf";
        string log_impl = "color_text";
        string log_output = "";
        string ipsec_impl = "xfrm";
        uint32_t initial_pool_size = 20;

        int32_t c;
        while ( ( c = getopt ( argc, argv, "Ff:l:o:i:p:h" ) ) != -1 ) {
            switch ( c ) {
                case 'F':
                    foreground = true;
                    break;
                case 'f':
                    configuration_filename = optarg;
                    break;
                case 'l':
                    log_impl = optarg;
                    break;
                case 'i':
                    ipsec_impl = optarg;
                    break;
                case 'p':
                    sscanf ( optarg, "%d", &initial_pool_size );
                    break;
                case 'o':
                    log_output = optarg;
                    break;
                case 'h': {
                    string version = "OpenIKEv2 version " + UtilsImpl::charToString ( OPENIKE_VERSION ) + " (http://openikev2.dif.um.es)\n";
                    fprintf ( stderr, version.c_str() );
                    fprintf ( stderr, "Usage:\n" );
                    fprintf ( stderr, "       openikev2 [-F] [-f config] [-l log_impl] [-i ipsec_impl] [-o log_output] [-p initial_pool_size]\n" );
                    fprintf ( stderr, "\n" );
                    fprintf ( stderr, "Where:\n" );
                    fprintf ( stderr, "       - log_impl can be \"color_text\" (default), \"text\" or \"html\"\n" );
                    fprintf ( stderr, "       - ipsec_impl can be \"xfrm\" (default) or \"pfkey\"\n" );
                    fprintf ( stderr, "       - config and log_output are filenames\n" );
                    fprintf ( stderr, "       - initial_pool_size is the intial thread pool size (default = 20)\n" );
                    fprintf ( stderr, "\n\n" );

                    return 0;
                }
                case '?':
                    if ( optopt == 'f' || optopt == 'l' || optopt == 'o' || optopt == 'i' )
                        fprintf ( stderr, "Option -%c requires an argument.\n", optopt );
                    else if ( isprint ( optopt ) )
                        fprintf ( stderr, "Unknown option `-%c'.\n", optopt );
                    else
                        fprintf ( stderr, "Unknown option character `\\x%x'.\n", optopt );
                    return 1;
                default:
                    abort ();
            }
        }

        // *********** SET RUNNING MODE ******************
        if ( !foreground ) {
            // Run in background
            int pid = fork();
            if ( pid != 0 ) {
                return 0;
            }
        }

        // At this poing, getpid() returns the real PID
        FILE* pid_file = fopen ( "/var/run/openikev2.pid", "wx" );
        if ( pid_file == NULL ) {
            cout << "It appears to exist other openikev2 instance running. If it isn't, remove the /var/run/openikev2.pid file and try again." << endl;
            exit ( -1 );
        }
        else {
            fprintf ( pid_file, "%d\n", getpid() );
            fclose ( pid_file );
        }

        //*********** SET IMPLEMENTATIONS ****************
        // thread controller
        thread_controller_posix.reset ( new ThreadControllerImplPosix() );
        ThreadController::setImplementation ( thread_controller_posix.get() );

        // log controller
        if ( log_impl == "text" )
            log_impl_openike.reset ( new LogImplText() );
        else if ( log_impl == "html" )
            log_impl_openike.reset ( new LogImplHtml() );
        else
            log_impl_openike.reset ( new LogImplColorText() );

        Log::setImplementation ( log_impl_openike.get() );

        if ( log_output != "" )
            log_impl_openike->open ( log_output );

        //Log::setLogMask(Log::LOG_ALL &  ~Log::LOG_ALRM);
        log_impl_openike->setLogMask ( Log::LOG_ALL );

        // alarm controller
        alarm_controller.reset ( new AlarmControllerImplOpenIKE ( 1000 ) );
        AlarmController::setImplementation ( alarm_controller.get() );

        // IKE_SA controller
        ike_sa_controller_openike.reset ( new IkeSaControllerImplOpenIKE ( initial_pool_size ) );
        IkeSaController::setImplementation ( ike_sa_controller_openike.get() );

        // crypto controller
        crypto_controller_openike.reset ( new CryptoControllerImplOpenIKE() );
        CryptoController::setImplementation ( crypto_controller_openike.get() );

        // network controller
        network_controller_openike.reset ( new NetworkControllerImplOpenIKE() );
        NetworkController::setImplementation ( network_controller_openike.get() );

        // aaa controller
        aaa_controller_radius.reset ( new AAAControllerImplRadius() );
        AAAController::setImplementation ( aaa_controller_radius.get() );

        // IPsec controller
        if ( ipsec_impl == "pfkey" )
            ipsec_controller.reset ( new IpsecControllerImplPfkeyv2() );
        else
            ipsec_controller.reset ( new IpsecControllerImplXfrm() );

        IpsecController::setImplementation ( ipsec_controller.get() );

	// Parse configuration file        
	auto_ptr<ConfigurerLibConfuse> configurer ( new ConfigurerLibConfuse ( configuration_filename, *log_impl_openike ) );

#ifdef EAP_SERVER_ENABLED	
	// Start radvd functionality
	network_controller_openike.get()->startRadvd();
#endif


        Configuration::getInstance().getGeneralConfiguration();


        
        ipsec_controller->printPolicies();

        //************************************************

        if ( foreground )
            Log::writeLockedMessage ( "OpenIKEv2", "Running version " + UtilsImpl::charToString ( VERSION ) + ": Mode=[FOREGROUND] Press CTRL+C to shutdown OpenIKEv2 daemon", Log::LOG_INFO, true );
        else {
            if ( log_output == "" )
                log_impl_openike->open ( "openikev2_log" );
            else
                log_impl_openike->open ( log_output );
            Log::writeLockedMessage ( "OpenIKEv2", "Running version " + UtilsImpl::charToString ( VERSION ) + ": Mode=[BACKGROUND] PID=[" + intToString ( getpid() ) + "]", Log::LOG_INFO, true );
        }
        //************************************************

        //************START OPENIKEv2*********************
        NetworkController::registerNotifyController ( 16403, auto_ptr<NotifyController> ( new NotifyController_AUTH_LIFETIME ) );
        NetworkController::registerNotifyController ( 16396, auto_ptr<NotifyController> ( new NotifyController_MOBIKE_SUPPORTED ) );
        NetworkController::registerNotifyController ( 16400, auto_ptr<NotifyController> ( new NotifyController_UPDATE_SA_ADDRESSES) );
        //************************************************

        // *********** START THREADS**********************
        Log::writeLockedMessage ( "OpenIKEv2", "Starting main thread", Log::LOG_THRD, true );
        ipsec_controller->start();
        alarm_controller->start();
        network_controller_openike->start();
        aaa_controller_radius->start();

        //************************************************

        Log::acquire();
        Log::writeMessage ( "OpenIKEv2", "Reading data from file: Path=[" + configuration_filename + "]", Log::LOG_CONF, true );
        Log::writeMessage ( "OpenIKEv2", Configuration::getInstance().toStringTab ( 1 ), Log::LOG_CONF, false );
        Log::release();




        signal ( SIGINT, termination_handler );
        signal ( SIGTERM, termination_handler );

        ExitObserver exit_observer;
        ControlInterface control_interface ( 6789 );
        control_interface.start();
        exit_observer.waitForExitNotify();

        ipsec_controller->cancel();
        alarm_controller->cancel();
        network_controller_openike->cancel();

        sleep ( 1 );
        //***********************************************************
    }
    catch ( Exception & ex ) {
        Log::writeLockedMessage ( "OpenIKEv2", ex.what(), Log::LOG_ERRO, true );
    }

    //**** END OF MAIN THREAD EXECUTION *****************************
    finalice();
    return EXIT_SUCCESS;
    //**** END OF MAIN THREAD EXECUTION *****************************
}

void finalice() {

    unlink ( "/var/run/openikev2.pid" );
    
    auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();

    bool flush_on_close = false;
    BoolAttribute* flush_on_close_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "flush_on_close" );
    if (flush_on_close_attr  != NULL )
        flush_on_close = flush_on_close_attr->value;
    if ( flush_on_close ) {
        IpsecController::flushIpsecPolicies();
        IpsecController::flushIpsecSas();
    }


    Log::writeLockedMessage ( "OpenIKEv2", "Stopped", Log::LOG_THRD, true );
}


