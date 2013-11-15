# INFORMACIÓN DEL PROGRAMA
# ---------------------------
# 
#       La información y ayuda se encuentra en el ejecutable del programa principal
#       Vease "motor.pl"
#
# 
# COPYRIGHT
# -----------
#  
#       This software is Copyright (c):
#               - Carlos Fuente Bermejo - carlos.fuentes@rediris.es
#               - David Rodriguez Galiano - david.rodriguez@soporte.rediris.es 
# 

package Net::Whois::RedIRIS;
use strict;

use vars qw($VERSION);
$VERSION = '6.000';
use Config;

use Data::Dumper;

# IP Libraries
use Data::Validate::IP;
use Data::Validate::Domain;
use Net::DNS;

use NetAddr::IP;
use Net::IP;
use Math::BigInt;
use Math::BigInt::Calc;

# SQL libraries
use CGI::Carp qw(fatalsToBrowser);
use DBI;

# LDAP libraries
use Net::LDAP;

# Whois libraries
use Net::Whois::Proxy;


###########################################################################################
# Gestiona la consulta en modo sencillo. Una IP o un domino o un hostname
sub singleMode{

	# Se recibe una referencia al objeto y una referencia del input (IP, hostname o domain)
        my ($configObj, $input) = @_;

        # Variable donde se alamacena la dirección IP en caso de ser un hostname
        my $ip = "";

        # Identificador de la conexion MySQL
        my $MySQLid = -1;

	# Identificador de la conexión a LDAP
	my $LDAPid = -1;

        # Almacena todos los datos de rangos, router, ... (información almacenada en MySQL) de una petición de whois
        my %MySQLResults = ();

        # Almacena los parametros de configuración y búsqueda de LDAP escritos en el fichero de configuración
        my %LDAPConfigParams = ();

        # Almacena las entradas de LDAP devueltas en cada búsqueda. (Es una variable auxiliar que se reutiliza en cada búsqueda)
        my $LDAPResults;

        # Almacena todos los resultados de las sucesivas búsquedas que se lanzan contra LDAP
        my %allHashResults = ();

        # Variable en la que devolvemos los resultados de las búsquedas de MySQL y LDAP (extraídos de %allHashResults) para una impresión bonita
        my $allStringResults;

        # Variable que almacena los valores de error de retorno de las funciones
        my $errCode = 0;

        if ($$input ne "" && defined $$input) {

		# Si no es un hostname ni un dominio ni una IP, devolvemos un error puesto que la cadena no es reconocida
                if (!isIP($$input) and !isHostname($$input, \$ip) and !isDomain($$input)){
                        $allStringResults = "La cadena '".$$input."' no es una dirección IP, ni hostname, ni un dominio.";
                        $configObj->writeLog( $allStringResults) if ($configObj->debug());
                        return "\t".$allStringResults."\n\n";
                }


               	# Si es un hostname, buscamos su dirección IP para realizar el whois
                # Un hostname, una IPv4 y una IPv6 se tratan de la misma manera
                if (isHostname($$input, \$ip)){
                        $configObj->writeLog( "El valor introducido '$$input' es un hostname y su dirección IP '".$ip."' es IPv4.") if ($configObj->debug() and $configObj->verbose());
                }
                else{
                        $ip = $$input;
                }


                # Comprobamos que es una dirección IP
                # El trato para una IPv4 o una IPv6 es el mismo. Solo difiere la consulta en MySQL, pero las consultas en LDAP son iguales
                if (isIP($ip)){
                        #IPv4
                        if (isIPv4($ip)){
                                $configObj->writeLog( "El valor introducido '$ip' es una dirección IPv4.") if ($configObj->debug() and $configObj->verbose());

                                # Conexión a base de datos para extraer el rango, acrónimo y copacode
                                $MySQLid = MySQLConnect($configObj); #$configObj ya es una referencia al objeto. No es el objeto
                                $errCode = MySQLQueryByIPv4($configObj, \$MySQLid, \$ip, \%MySQLResults);
                                MySQLDisconnect($configObj, \$MySQLid);
                        }
                        #IPv6
                        elsif (isIPv6($ip)){
                                $configObj->writeLog( "El valor introducido '$ip' es una dirección IPv6.") if ($ip eq $$input and $configObj->debug() and $configObj->verbose());
                                
				# Conexión a base de datos para extraer el rango, acrónimo y copacode
                                $MySQLid = MySQLConnect($configObj);
                                $errCode = MySQLQueryByIPv6($configObj, \$MySQLid, \$ip, \%MySQLResults);
                                MySQLDisconnect($configObj, \$MySQLid);
                        }
                }

                # Comprobamos que el input es el nombre de un dominio
                # Compruebamos también que no sea también un hostname. Esto se debe a que, por ejemplo, dominio.es y www.dominio.es
		# a veces resuelven a la misma IP y otras no
                # Por ello, si un input resuelve como hostname, no lo resolvemos como dominio para evitar errores
                if (!isHostname($$input, \$ip) and isDomain($$input)){
                        $configObj->writeLog( "El valor introducido '$$input' es un dominio.") if ($configObj->debug() and $configObj->verbose());

                        $MySQLid = MySQLConnect($configObj);
                        $errCode = MySQLQueryByDomain($configObj, \$MySQLid, $input, \%MySQLResults);
                        MySQLDisconnect($configObj, \$MySQLid);
                }

                # Independientemente que sea un hostname, un dominio o una IP siempre devolvemos un hash (%MySQLResults) con los resultados de la consulta
                # Al menos, en estas consultas, debe aparecer el acrónimo y copacode, además del nombre de la institución y otros datos de interés no obligatorios

                # Si las consultas en la base de datos devuelve -1 significa que no hay ningún resultado relacionado con instituciones de RedIRIS
                # Por ello devolvemos el resultado del whois que devuelva el RIR más adecuado
                if ($errCode == -1){
                        my $auxMsg = "No se han encontrado resultados en las bases de datos -MySQL- de RedIRIS.";
                        $allStringResults .= "\t".$auxMsg."\n";
			$configObj->writeLog( $auxMsg) if $configObj->debug();
                        $auxMsg = "El valor devuelto pertenece a Regional Internet Registry (RIR) más adecuado.";
                        $allStringResults .= "\t".$auxMsg."\n\n";
			$configObj->writeLog( $auxMsg) if $configObj->debug();

                        my $whois = new Net::Whois::Proxy;
                        $allStringResults .= $whois->whois($ip);
                        return $allStringResults;
                }

                # Independientemente que sea un hostname, un dominio o una IP siempre devolvemos un hash (%MySQLResults) con los resultados de la consulta
                # Al menos, en estas consultas, debe aparecer el acrónimo y copacode, además del nombre de la institución y otros datos de interés no obligatorios

                # Con el acrónimo y el copacode extraídos de MySQL y con la configuración de LDAP accedemos a LDAP para
                # extraer el resto de información de las instituciones (dirección, contactos, ...)

                # Conexión a LDAP para extraer los datos de la institución con el acrónimo y copacode extraídos de MySQL
		$LDAPid = LDAPConnect($configObj, "Institution");

		$LDAPResults = LDAPQuery($configObj, \$LDAPid, "Institution", $MySQLResults{'copacode'});

		$allHashResults{'institution'} = $LDAPResults;

                LDAPDisconnect($configObj, \$LDAPid);
                if ($LDAPResults == -1){
                        $allStringResults = "[EXCEPCIÓN GRAVE] Búsqueda fallida en LDAP / Búsqueda por institución.\n";
                        $configObj->writeLog( $allStringResults);
			$allStringResults = "\t".$allStringResults."\n\n";
                        return $allStringResults;
                }

                # Conexión a LDAP para extraer los datos de los contactos oficiales con el acrónimo extraídos de MySQL
                $LDAPid = LDAPConnect($configObj, "IRISPerson");
                $LDAPResults = LDAPQuery($configObj, \$LDAPid, "IRISPerson", $MySQLResults{'copacode'});

                $allHashResults{'irisPerson'} = $LDAPResults;

                LDAPDisconnect($configObj, \$LDAPid);

                if ($LDAPResults == -1){
                       	$allStringResults = "[EXCEPCIÓN GRAVE] Búsqueda fallida en LDAP / Búsqueda por contactos oficiales.\n";
                       	$configObj->writeLog( $allStringResults);
			$allStringResults = "\t".$allStringResults."\n\n";
                      	return $allStringResults;
                }

                # Conexión a LDAP para extraer los datos de los contactos CERT con el acrónimo extraídos de MySQL
                $LDAPid = LDAPConnect($configObj, "CERTPerson");
                $LDAPResults = LDAPQuery($configObj, \$LDAPid, "CERTPerson", $MySQLResults{'acronimo'});

                $allHashResults{'certPerson'} = $LDAPResults;

                LDAPDisconnect($configObj, \$LDAPid);

                if ($LDAPResults == -1){
                        $allStringResults = "[EXCEPCIÓN GRAVE] Búsqueda fallida en LDAP / Búsqueda por contactos de seguridad.\n";
                        $configObj->writeLog( $allStringResults);
                        $allStringResults = "\t".$allStringResults."\n\n";
			return $allStringResults;
                }

                # Imprime los resultados de forma bonita que se han almaecendo en el string
                $allStringResults = prettyPrint(\%MySQLResults, \%allHashResults);
		return $allStringResults;

        # Si no es una dirección IP, ni un hostname, ni un dominio, entonces la cadena no es valida
        }
        elsif (length($$input) == 0){
                $configObj->writeLog( "La cadena introducida tiene longitud 0. No se realiza ninguna búsqueda en el whois.") if $configObj->debug();
        }
        else {
                $allStringResults = "La cadena no está definida o se desconoce qué tipo es.";
                $configObj->writeLog( $allStringResults) if $configObj->debug();
        }

        # Independientemente de si la búsqueda es satisfactoria, o no, desconectamos al cliente
        return;
}


###########################################################################################
# Extrae las direcciones de los contactos de seguridad operativos dado una IP o un domino o un hostname
sub RT_CERTMode{

        # Se recibe una referencia al objeto y una referencia del input (IP, hostname o domain)
        my ($configObj, $input) = @_;

        # Variable donde se alamacena la dirección IP en caso de ser un hostname
        my $ip = "";

        # Identificador de la conexion MySQL
        my $MySQLid = -1;

        # Identificador de la conexión a LDAP
        my $LDAPid = -1;

        # Almacena todos los datos de rangos, router, ... (información almacenada en MySQL) de una petición de whois
        my %MySQLResults = ();

        # Almacena los parametros de configuración y búsqueda de LDAP escritos en el fichero de configuración
        my %LDAPConfigParams = ();

        # Almacena las entradas de LDAP devueltas en cada búsqueda. (Es una variable auxiliar que se reutiliza en cada búsqueda)
        my $LDAPResults;

        # Almacena todos los resultados de las sucesivas búsquedas que se lanzan contra LDAP
        my %allHashResults = ();

        # Variable en la que devolvemos los resultados de las búsquedas de MySQL y LDAP (extraídos de %allHashResults) para una impresión bonita
        my $allStringResults;

        # Variable que almacena los valores de error de retorno de las funciones
        my $errCode = 0;

        if ($$input ne "" && defined $$input) {

                # Si no es un hostname ni un dominio ni una IP, devolvemos un error puesto que la cadena no es reconocida
                if (!isIP($$input) and !isHostname($$input, \$ip) and !isDomain($$input)){
                        $allStringResults = "La cadena '".$$input."' no es una dirección IP, ni hostname, ni un dominio.";
                        $configObj->writeLog( $allStringResults) if ($configObj->debug());
			return;
                }
                # Si es un hostname, buscamos su dirección IP para realizar el whois
                # Un hostname, una IPv4 y una IPv6 se tratan de la misma manera
                if (isHostname($$input, \$ip)){
                        $configObj->writeLog( "El valor introducido '$$input' es un hostname y su dirección IP '".$ip."' es IPv4.") if ($configObj->debug() and $configObj->verbose());
                }
                else{
                        $ip = $$input;
                }

                # Comprobamos que es una dirección IP
                # El trato para una IPv4 o una IPv6 es el mismo. Solo difiere la consulta en MySQL, pero las consultas en LDAP son iguales
                if (isIP($ip)){

                        #IPv4
                        if (isIPv4($ip)){
                                $configObj->writeLog( "El valor introducido '$ip' es una dirección IPv4.") if ($configObj->debug() and $configObj->verbose());

                                # Conexión a base de datos para extraer el rango, acrónimo y copacode
                                $MySQLid = MySQLConnect($configObj); #$configObj ya es una referencia al objeto. No es el objeto
                                $errCode = MySQLQueryByIPv4($configObj, \$MySQLid, \$ip, \%MySQLResults);
                                MySQLDisconnect($configObj, \$MySQLid);
                        }
                        #IPv6
                        elsif (isIPv6($ip)){
                                $configObj->writeLog( "El valor introducido '$ip' es una dirección IPv6.") if ($ip eq $$input and $configObj->debug() and $configObj->verbose());

                                # Conexión a base de datos para extraer el rango, acrónimo y copacode
                                $MySQLid = MySQLConnect($configObj);
                                $errCode = MySQLQueryByIPv6($configObj, \$MySQLid, \$ip, \%MySQLResults);
                                MySQLDisconnect($configObj, \$MySQLid);
                        }
                }

                # Comprobamos que el input es el nombre de un dominio
                # Compruebamos también que no sea también un hostname. Esto se debe a que, por ejemplo, dominio.es y www.dominio.es a veces resuelven a la misma IP y otras no
                # Por ello, si un input resuelve como hostname, no lo resolvemos como dominio para evitar errores
                if (!isHostname($$input, \$ip) and isDomain($$input)){
                        $configObj->writeLog( "El valor introducido '$$input' es un dominio.") if ($configObj->debug() and $configObj->verbose());

                        $MySQLid = MySQLConnect($configObj);
                        $errCode = MySQLQueryByDomain($configObj, \$MySQLid, $input, \%MySQLResults);
                        MySQLDisconnect($configObj, \$MySQLid);
                }
               # Independientemente que sea un hostname, un dominio o una IP siempre devolvemos un hash (%MySQLResults) con los resultados de la consulta
                # Al menos, en estas consultas, debe aparecer el acrónimo y copacode, además del nombre de la institución y otros datos de interés no obligatorios

                # Si las consultas en la base de datos devuelve -1 significa que no hay ningún resultado relacionado con instituciones de RedIRIS
                # Por ello devolvemos el resultado del whois que devuelva el RIR más adecuado
                if ($errCode == -1){
                        my $auxMsg = "No se han encontrado resultados en las bases de datos -MySQL- de RedIRIS.";
                        $allStringResults .= "\t".$auxMsg."\n";
                        $configObj->writeLog( $auxMsg) if $configObj->debug();
               		return;
		 }

                # Conexión a LDAP para extraer los datos de los contactos CERT con el acrónimo extraídos de MySQL
                $LDAPid = LDAPConnect($configObj, "CERTPerson");
                $LDAPResults = LDAPQuery($configObj, \$LDAPid, "RTCERTPerson", $MySQLResults{'acronimo'});

                $allHashResults{'certPerson'} = $LDAPResults;

                LDAPDisconnect($configObj, \$LDAPid);

                if ($LDAPResults == -1){
                        $allStringResults = "[EXCEPCIÓN GRAVE] Búsqueda fallida en LDAP / Búsqueda por contactos de seguridad.\n";
                        $configObj->writeLog( $allStringResults);
                	return;
		}

                # Imprime los resultados de forma bonita que se han almaecendo en el string
                $allStringResults = RTCERTPrint(\%MySQLResults, \%allHashResults);
                return $allStringResults;

        # Si no es una dirección IP, ni un hostname, ni un dominio, entonces la cadena no es valida
        }
        elsif (length($$input) == 0){
                $configObj->writeLog( "La cadena introducida tiene longitud 0. No se realiza ninguna búsqueda en el whois.") if $configObj->debug();
        }
        else {
                $allStringResults = "La cadena no está definida o se desconoce qué tipo es.";
                $configObj->writeLog( $allStringResults) if $configObj->debug();
        }

        # Independientemente de si la búsqueda es satisfactoria, o no, desconectamos al cliente
        return;
}

###########################################################################################
# Chequea si la cadena introducida es una dirección IP
sub isIP {
        my ($query) = @_;
        if (isIPv4($query) || isIPv6($query) ) {
                return 1;
        }
        return 0;
}


###########################################################################################
# Chequea si la cadena introducida es una IPv4
sub isIPv4 {
        my ($query) = @_;
        my $ip = Data::Validate::IP->new();
        if ( $ip->is_ipv4($query) ) {
                return 1;
        }
        return 0;
}


###########################################################################################
# Chequea si la cadena introducida es una IPv6
sub isIPv6 {
        my ($query) = @_;
        my $ip = Data::Validate::IP->new();
        if ( $ip->is_ipv6($query)) {
                return 1;
        }
        return 0;
}


###########################################################################################
# Chequea si la cadena introducida es un hostname. 
# En caso afirmativo la función devuelve un 1 de forma directa y a través del argumento IP devuelve la IP asociada al hotname indicado
# En caso contrario devuelve un 0
sub isHostname {
        my $query = shift;
        my $ip = shift;

        my $res = Net::DNS::Resolver->new(
		        recurse     	=> 0,
			tcp_timeout 	=> 1,
			udp_timeout	=> 1,
	);
	
	# my $res = Net::DNS::Resolver->new();	# BORRAR
        my $result = $res->search($query);
        if ($result) {
                foreach my $rr ($result->answer) {
                        if ($rr->type eq "A") {
                                $$ip = $rr->address;
                                return 1;
                        }
                }
        }
   
	return 0;
}



###########################################################################################
# Chequea si la cadena introducida es un dominio
sub isDomain {
   my ($querystring) = @_;

   my $v = Data::Validate::Domain->new();
   if ($v->is_domain($querystring)) {

=problem
      my $res = Net::DNS::Resolver->new(
                        recurse         => 0,
                        tcp_timeout     => 1,
                        udp_timeout     => 1,
        );
=cut
      
      my $res = Net::DNS::Resolver->new();
      my $query = $res->query($querystring, "SOA");
      if ($query) {
         return 1;
      }
   }

   return 0;
}


###########################################################################################
# Conexión a una base de datos de acuerdo a los parámetros del fichero de configuración 
sub MySQLConnect {
	
	my $configObj = shift;

	my $connection;

	my $source = "DBI:mysql:".$configObj->MySQLDatabase().";host=".$configObj->MySQLHost().";port=".$configObj->MySQLPort();
	$connection = DBI->connect($source, $configObj->MySQLUser(), $configObj->MySQLPassword()) or die $configObj->writeLog( "Fallo al conectar a ".$source.": ".$connection->errstr.".");
	$configObj->writeLog( "Conexión a base de datos realizada satisfactoriamente con id ".$connection.".") if $configObj->debug();

        return $connection;

}


###########################################################################################
# Cierra una conexión MySQL dado su identificador
sub MySQLDisconnect {
	my ($configObj, $connection) = @_;
	
	$$connection->disconnect;
	$configObj->writeLog( "Cierre de conexión a base de datos realizada satisfactoriamente.") if $configObj->debug();
}


###########################################################################################
# Realiza una query dada una dirección IP para obtener el rango
sub MySQLQueryByIPv4 {
        my ($configObj, $connection, $inputIP, $hashResult) = @_;

	# Compruebo si es una IPv4
	if (isIPv4($$inputIP)){
	
		my $ip = new NetAddr::IP $$inputIP;
		my $integerIP = $ip->numeric();

		$configObj->writeLog ( "La IP $ip se ha convertido en el entero $integerIP.") if ($configObj->debug() and $configObj->verbose());

		# Calculamos el numero de tuplas que vamos a encontrar con la búsqueda	
		my $query = "SELECT `rangosred`.`id` AS id, `rangosred`.`CIDR` AS cidr, `acr2copa`.`ACRONIMO` AS acronimo, `acr2copa`.`DESCRIPCION` AS descripcion, `rangosred`.`ROUTER` AS router, `rangosred`.`ASN` AS asn, `acr2copa`.`COPACODE` AS copacode, `rangosred`.`LASTIP` - `rangosred`.`FIRSTIP` AS diferencia FROM `NOCData`.`rangosred`, `NOCData`.`acr2copa` 
WHERE `rangosred`.`PTR_ACR2COPA` = `acr2copa`.`id` AND `rangosred`.`FIRSTIP` <= '".$integerIP."' AND `rangosred`.`LASTIP` >= '".$integerIP."' AND `rangosred`.`tipo` = '4' ORDER BY diferencia ASC;";
	
		my $queryResults = $$connection->prepare($query);

        	$queryResults->execute or die $configObj->writeLog( "Imposible ejecutar consulta:$$connection->err, $$connection->errstr.");

		# Si no hay resultados, salimos de la función
		if ($queryResults->rows == 0) {
			$configObj->writeLog( "No se han obtenido resultados en la búsqueda.") if $configObj->debug();
                        return -1;
                } else {

                        ($hashResult->{'id'}, $hashResult->{'cidr'}, $hashResult->{'acronimo'}, $hashResult->{'descripcion'}, $hashResult->{'router'}, $hashResult->{'asn'}, $hashResult->{'copacode'}, my $dif) = $queryResults->fetchrow_array;
		}	
	}
	
        return 0;
}


###########################################################################################
# Realiza una query dada una dirección IP para obtener el rango
sub MySQLQueryByIPv6 {

	my ($configObj, $connection, $inputIP, $hashResult) = @_;

	# Desgranamos la IPv6 para realizar búsquedas en la base de datos
        # IP (128b) = parteAlta (64b) | parteBaja (64b) 

        my $CALC = 'Math::BigInt::Calc';

        my $objetoIP = new Net::IP($$inputIP,6);
        my $binaryIP = ($objetoIP->binip());                            # Ipv6 en binario (128 bits)

        my $altaBin = substr ($binaryIP, 0, 64);                        # primeros 64 bits
        my $IPParteAlta = $CALC->_str($CALC->_from_bin("0b".$altaBin));	# pasar a BigINT para realizar la búsqueda en MySQL

      	my $bajaBin = substr ($binaryIP, 64,64);                        # últimos 64 bits
        my $IPParteBaja = $CALC->_str($CALC->_from_bin("0b".$bajaBin));


        # Calculamos el numero de tuplas que vamos a encontrar con la búsqueda  
	my $query = "SELECT `rangosred`.`id` AS id, `rangosred`.`CIDR` AS cidr, `acr2copa`.`ACRONIMO` AS acronimo, `acr2copa`.`DESCRIPCION` AS descripcion, `rangosred`.`ROUTER` AS router, `rangosred`.`ASN` AS asn, `acr2copa`.`COPACODE` AS copacode FROM `NOCData`.`rangosred`, `NOCData`.`acr2copa` WHERE `rangosred`.`PTR_ACR2COPA` = `acr2copa`.`id` AND `rangosred`.`FIRSTIPTOP` <= '".$IPParteAlta."'  AND `rangosred`.`LASTIPTOP` >= '".$IPParteAlta."' AND `rangosred`.`FIRSTIP` <= '".$IPParteBaja."' AND `rangosred`.`LASTIP` >= '".$IPParteBaja."' AND `rangosred`.`tipo` = '6';";

        my $queryResults = $$connection->prepare($query);

        $queryResults->execute or die $configObj->writeLog( "Imposible ejecutar consulta:$$connection->err, $$connection->errstr.");

        # Si no hay resultados, salimos de la función
        if ($queryResults->rows == 0) {
        	$configObj->writeLog( "No se han obtenido resultados en la búsqueda.") if $configObj->debug();
                return -1;
      	} else {

      	       ($hashResult->{'id'}, $hashResult->{'cidr'}, $hashResult->{'acronimo'}, $hashResult->{'descripcion'}, $hashResult->{'router'}, $hashResult->{'asn'}, $hashResult->{'copacode'
}, my $dif) = $queryResults->fetchrow_array;
        }

        return 0;
}


###########################################################################################
# Realiza una query dada un dominio para obtener el acrnimo y copacode
sub MySQLQueryByDomain {
        my ($configObj, $connection, $inputDomain, $hashResult) = @_;

        # Compruebo si es una IPv4
        if (isDomain($$inputDomain)){

                # Calculamos el numero de tuplas que vamos a encontrar con la búsqueda
		my $query = "SELECT `rangosred`.`id` AS id, `rangosred`.`CIDR` AS cidr, `acr2copa`.`ACRONIMO` AS acronimo, `acr2copa`.`DESCRIPCION` AS descripcion, `rangosred`.`ROUTER` AS router, `rangosred`.`ASN` AS asn, `acr2copa`.`COPACODE` AS copacode FROM `NOCData`.`DNS_SecundariosDirectos`, `NOCData`.`acr2copa`, `NOCData`.`rangosred` WHERE `DNS_SecundariosDirectos`.`zona`='".$$inputDomain."' AND `DNS_SecundariosDirectos`.`PTR_ACR2COPA` = `acr2copa`.`id` AND `acr2copa`.`id` = `rangosred`.`PTR_ACR2COPA`;";
 
                my $queryResults = $$connection->prepare($query);

                $queryResults->execute or die $configObj->writeLog( "Imposible ejecutar consulta:$$connection->err, $$connection->errstr.");

		my $numTuplas = $queryResults->rows;

                # Si no hay resultados, salimos de la función
                if ($numTuplas == 0) {
                        $configObj->writeLog( "No se han obtenido resultados en la búsqueda por dominio.") if $configObj->debug();
                        return -1;
                } 
		elsif ($numTuplas == 1){
			# Si solo se ha obtenido un resultado, devolvemos los valores
			 $configObj->writeLog( "Ha habido un único resultado en la búsqueda por dominio.") if ($configObj->debug() and $configObj->verbose());
			($hashResult->{'id'}, $hashResult->{'cidr'}, $hashResult->{'acronimo'}, $hashResult->{'descripcion'}, $hashResult->{'router'}, $hashResult->{'asn'}, $hashResult->{'copacode'
}, my $dif) = $queryResults->fetchrow_array;
		}
		else {
			# Si devuelve mas de un resultado devolvemos todos los valores
			$configObj->writeLog( "Ha habido más de un resultado en la búsqueda por dominio") if ($configObj->debug() and $configObj->verbose());
			while ((my $id, my $cidr, my $acronimo, my $descripcion, my $router, my $asn, my $copacode) = $queryResults->fetchrow_array){
				if ($id){
					$hashResult->{'id'} = $id;
				}
				if ($cidr){
					$hashResult->{'cidr'} .= $cidr." ";
				}
				if ($acronimo){
					$hashResult->{'acronimo'} = $acronimo;
				}
				if ($descripcion){
					$hashResult->{'descripcion'} = $descripcion;
				}
				if ($router){
					$hashResult->{'router'} .= $router." ";
				}
				if ($asn){
					$hashResult->{'asn'} = $asn;
				}	
				if ($copacode){
					$hashResult->{'copacode'} = $copacode;
				}
			}
                }
        }

        return 0;
}


###########################################################################################
# Conexión a un LDAP de acuerdo a los parámetros de configuración pasados por argumento 
sub LDAPConnect {
	
	my $configObj = shift;
	my $type = shift;        

	my $connection = -1;

	if ($type eq "Institution"){
		$connection = Net::LDAP->new($configObj->LDAPHost_Institution(), port => $configObj->LDAPPort_Institution(), timeout => $configObj->LDAPTimeOut_Institution(), async => 1) or die $configObj->writeLog( "Fallo al conectarse a LDAP '".$configObj->LDAPHost_Institution()."'.");
	
		$connection->bind($configObj->LDAPBindDN_Institution(), password => $configObj->LDAPBindPassword_Institution());	
	}
	elsif ($type eq "IRISPerson"){
                $connection = Net::LDAP->new($configObj->LDAPHost_IRISPerson(), port => $configObj->LDAPPort_IRISPerson(), timeout => $configObj->LDAPTimeOut_IRISPerson(), async => 1) or die $configObj->writeLog( "Fallo al conectarse a LDAP '".$configObj->LDAPHost_IRISPerson()."'.");
        
                $connection->bind($configObj->LDAPBindDN_IRISPerson(), password => $configObj->LDAPBindPassword_IRISPerson());
	}
	elsif ($type eq "CERTPerson"){
                $connection = Net::LDAP->new($configObj->LDAPHost_CERTPerson(), port => $configObj->LDAPPort_CERTPerson(), timeout => $configObj->LDAPTimeOut_CERTPerson(), async => 1) or die $configObj->writeLog( "Fallo al conectarse a LDAP '".$configObj->LDAPHost_CERTPerson()."'.");

                $connection->bind($configObj->LDAPBindDN_CERTPerson(), password => $configObj->LDAPBindPassword_CERTPerson());

	}

        $configObj->writeLog( "Conexión a LDAP (rama ".$type.") realizada satisfactoriamente con id ".$connection.".") if $configObj->debug();

        return $connection;

}


###########################################################################################
# Cierra una conexión LDAP dado su identificador
sub LDAPDisconnect {
	my ($configObj, $connection) = @_;
        $$connection->unbind;
        $configObj->writeLog( "Cierre de conexión a LDAP realizada satisfactoriamente.") if $configObj->debug();
}



###########################################################################################
# Ejecuta una consulta sobre LDAP dado el id de la conexión, la base, el filtro, y el valor que 
# hay que sustituir en el filtro por la expresión regular
sub LDAPQuery {

	my ($configObj, $LDAPid, $type, $stringToReplace) = @_;
	
	my $baseDN = "";
	my $filter = "";
	my $result = "";

	if ($type eq "Institution"){

		$baseDN = $configObj->LDAPBaseDN_Institution();
		$filter = $configObj->LDAPFilter_Institution();

		$filter =~ s/VALUE_DATA/$stringToReplace/;
	        
		$result = $$LDAPid->search (
			base => $baseDN, 
			filter => $filter,
			scope => 'sub',
		);
	}
	elsif ($type eq "IRISPerson"){

               	$baseDN = $configObj->LDAPBaseDN_IRISPerson();
                $filter = $configObj->LDAPFilter_IRISPerson();

                $filter =~ s/VALUE_DATA/$stringToReplace/;
        	$configObj->writeLog($filter) if $configObj->debug();
                $result = $$LDAPid->search (
                        base => $baseDN, 
                        filter => $filter,
                        scope => 'sub',
                );
	}
	elsif ($type eq "CERTPerson"){

                $baseDN = $configObj->LDAPBaseDN_CERTPerson();
                $filter = $configObj->LDAPFilter_CERTPerson();

                $filter =~ s/VALUE_DATA/$stringToReplace/;

                $result = $$LDAPid->search (
                        base => $baseDN,
                        filter => $filter,
                        scope => 'sub',
                );
	}
	elsif ($type eq "RTCERTPerson"){

                $baseDN = $configObj->LDAPBaseDN_CERTPerson();
                $filter = "(&(|(businessCategory=RT-CERT-REG)(businessCategory=RT-CERT))(o=VALUE_DATA))";

                $filter =~ s/VALUE_DATA/$stringToReplace/;

                $result = $$LDAPid->search (
                        base => $baseDN,
                        filter => $filter,
                        scope => 'sub',
                );
        }


	if ($result->error eq "Success"){
		if (scalar ($result->entries) > 0){
			my @aux = $result->entries;
			return \@aux;
		}
		else{
			$configObj->writeLog( "No se han encontrado entradas para LDAP con los siguientes parametros:") if $configObj->debug();
			$configObj->writeLog( "\tBaseDN: '".$baseDN."' - Filtro: '".$filter."'.") if $configObj->debug();
			return 0;
		}
	}
	else{
		$configObj->writeLog( "Búsqueda inválida [".$result->code."]: ".$result->error.".") if $configObj->debug();
		return -1;
	}

	return -1;
}


###########################################################################################
# Convierte los valores devueltos por MySQL en un string
sub e2sMySQL {
	my $entry = shift;
	my $string = undef;

	if ($entry->{'descripcion'}){
		$string .= "Institución:\t".$entry->{'descripcion'}."\n";
	}
	else{
		$string .= "Institución:\t-\n";
	}

	if ($entry->{'acronimo'}){
		$string .= "Acrónimo:   \t".$entry->{'acronimo'}."\n";
	}
	else{
                $string .= "Acrónimo:    \t-\n";
	}

	if ($entry->{'cidr'}){
		$string .= "CIDR:       \t".$entry->{'cidr'}."\n";
	}
	else{
		$string .= "CIDR:       \t-\n";
	}

	if ($entry->{'router'}){
		$string .= "Router:     \t".$entry->{'router'}."\n";
	}
	else{
		$string .= "Router:     \t-\n";
	}
	
	if ($entry->{'asn'}){
		$string .= "ASN:        \t".$entry->{'asn'}."\n";
	}
	else{
		$string .= "ASN:        \t-\n";
	}
	$string .= "\n";
	return $string;
}

###########################################################################################
# Convierte una entrada de LDAP tipo INSTITUCION en un string
sub e2sInstitucion {
   my $entry = shift;
   my $string;
   my %atributos = (
                    "o"                             => "Organización",
                    "associatedDomain"              => "Dominio",
                    "telephoneNumber"               => "Telefono",
                    "facsimileTelephoneNumber"      => "FAX",
                    "postalAddress"                 => "Dirección",
                    "postalCode"                    => "Código Postal",
                    "l"                             => "Ciudad",
                    "st"                            => "Provincia",
                    "labeledURI"                    => "URL",
                    );

   foreach my $attr (keys %atributos) {
      if ($entry->exists($attr)) {
         $string .= $atributos{$attr}.":\t";
         $string .= join " - ",@{$entry->get_value($attr, asref => 1)};
         $string .= "\n";
      }
   }
   $string .= "\n";
   return $string;
}


###########################################################################################
# Convierte una entrada de LDAP tipo INSTITUCION en un string
sub e2sPerson {
        my $entry = shift;
        my %atributos = (
                    "cn"                            => "Nombre y apellidos",
                    "description"                   => "Cargo/ocupación",
                    "businessCategory"              => "Tipo de contacto",
                    "title"                         => "Título",
                    "mail"                          => "E-mail",
                    "telephoneNumber"               => "Telefono",
                    "facsimileTelephoneNumber"      => "FAX",
                    "schacUserStatus"               => "Rol",
                    );
	my %roles = (   'pec' => 'RT-CERT',
                        'resmanager' => 'Responsable de investigación',
                        'techcontact' => 'Contacto técnico',
                        'pen' => 'Contacto NOC',
                        'per' => 'Punto de enlance con RedIRIS',
                        'sign' => 'Firmante de la institución',
                );


        my $string .= "- 8>< ----\n\n";
	foreach my $attr (keys %atributos) {
                if ($entry->exists($attr)) {
                        if ($attr eq "schacUserStatus") {
                                my $values = $entry->get_value($attr, asref => 1);
                               	foreach my $value (@{$values}) {
                                        if ($value =~ /:affiliation:role:/) {
                                                $value =~ /urn:mace:terena.org:schac:userStatus:es:rediris.es:affiliation:role:(.*)/;
                                                my $role = $1;
                                                if (exists $roles{$role} ) {
                                                        $role = $roles{$role};
                                                }
                                                $string .= $atributos{$attr}.":\t";
                                                if ($role) {
                                                        $string .= $role."\n";
                                                }
                                        }
                                }

                        } else {
                                $string .= $atributos{$attr}.":\t";
                                $string .= join " - ",@{$entry->get_value($attr, asref => 1)};
                                $string .= "\n";
                        }
        }
        }
        $string .= "\n";
        return $string;
}


###########################################################################################
# Escribe en un string toda la información. La escribe con formato legible para mostrar en pantalla
sub prettyPrint{
	my $MySQLResults = shift;
	my $LDAPResults = shift;

	my $prettyString = "";

	# Pasamos a string los valores MySQL
	$prettyString  = "% Institucion, acronimo y rangos asignados:\n";
	$prettyString .= "---------------------------------------------------------\n\n";

	$prettyString .= e2sMySQL($MySQLResults);	
	
	$prettyString .="\n\n";


	# Pasamos a string los valores de la institución
	$prettyString .= "% Ubicacion y contacto generico de la institucion:\n";
	$prettyString .= "---------------------------------------------------------\n\n";
	
	if ($LDAPResults->{'institution'} != 0 ) {
		foreach my $entry (@{$LDAPResults->{'institution'}}) {
			$prettyString .= e2sInstitucion($entry);
        	}
	}
	else{
                $prettyString .= "\tNo figura informacion generica de la institucion.\n\n";
	}

        $prettyString .="\n\n";


        # Pasamos a string los valores de los contactos oficiales
        $prettyString .= "% Contactos oficiales de la institucion:\n";
        $prettyString .= "---------------------------------------------------------\n\n";
	
	if ($LDAPResults->{'irisPerson'} != 0 ) { 
	        foreach my $entry (@{$LDAPResults->{'irisPerson'}}) {
        	        $prettyString .= e2sPerson($entry);
        	}
	}
	else{
                $prettyString .= "\tNo figuran contactos oficiales. Accede a ComunIRIS para contactar con el/los PER/s.\n\n";
	}

        $prettyString .="\n\n";

        # Pasamos a string los valores de los contactos CERT
        $prettyString .= "% Contactos de seguridad operativos:\n";
        $prettyString .= "---------------------------------------------------------\n\n";

	if ($LDAPResults->{'certPerson'} != 0 ) {
        	foreach my $entry (@{$LDAPResults->{'certPerson'}}) {
               		$prettyString .= e2sPerson($entry);
        	}
	}
	else{
		$prettyString .= "\tNo figuran contactos de seguridad. Accede a ComunIRIS para contactar con el/los PCS/s.\n\n";
	}

	return $prettyString;

}


###########################################################################################
# Escribe en un string toda la información. La escribe con formato legible para mostrar en pantalla
sub RTCERTPrint{
        my $MySQLResults = shift;
        my $LDAPResults = shift;

        my $prettyString = "";
	my $prettyRT_CERT_REG = "";
	my $prettyRT_CERT = "";

	# Pasamos a string los valores de los contactos CERT
        if ($LDAPResults->{'certPerson'} != 0 ) {
		foreach my $entry (@{$LDAPResults->{'certPerson'}}) {

			my @businessCategory = @{$entry->get_value('businessCategory', asref => 1)};

			my $esContactoRegional = 0;
			my $esContactoInstitucional = 0;

			foreach my $bc (@businessCategory) {
				if ($bc eq 'RT-CERT'){
					$esContactoInstitucional++;
				}
				if ($bc eq 'RT-CERT-REG'){
                                        $esContactoRegional++;
                                }
			}

			# Miramos posibles fallos, es decir, que una dirección de correo no sea
                        # contacto institucional y contacto regional

                       	# Existe contacto institucional y regional. Sólo lo utilizamos como institucional
                       	if ($esContactoInstitucional != 0 and $esContactoRegional != 0){
                                $prettyRT_CERT .= e2RTsPerson($entry);
                       	}
                       	# Existe sólo contacto institucional
                       	elsif ($esContactoInstitucional !=0 and $esContactoRegional == 0){
                                $prettyRT_CERT .= e2RTsPerson($entry);
                       	}
                       	# Existe sólo contacto regional
                       	elsif ($esContactoInstitucional ==0 and $esContactoRegional != 0){
                                $prettyRT_CERT_REG .= e2RTsPerson($entry);
                       	}
                }

        }

        #Generando la salida en forma URL
        if ($prettyRT_CERT ne "" and $prettyRT_CERT_REG ne ""){
                $prettyString = "&Requestors=".$prettyRT_CERT;
                chop ($prettyString);
                $prettyString .= "&Cc=".$prettyRT_CERT_REG;
                chop ($prettyString);
       	}
       	elsif ($prettyRT_CERT ne "" and $prettyRT_CERT_REG eq ""){
                $prettyString = "&Requestors=".$prettyRT_CERT;
                chop ($prettyString);
       	}
       	elsif ($prettyRT_CERT eq "" and $prettyRT_CERT_REG ne ""){
                $prettyString = "&Cc=".$prettyRT_CERT_REG;
                chop ($prettyString);
       	}
       	else{
		$prettyString = "";
	}


	return $prettyString;
}

###########################################################################################
# Devuelve la direccion de correo electronico de los contactos CERT de la búsqueda LDAP realizada
sub e2RTsPerson {
        my $entry = shift;

        my %atributos = ("mail" => "E-mail",);

        my $string .= "";

        foreach my $attr (keys %atributos) {
                if ($entry->exists($attr)) {
                	$string .= join " - ",@{$entry->get_value($attr, asref => 1)};
                      	$string .= ",";
                }
        }

        return $string;
}

1;
