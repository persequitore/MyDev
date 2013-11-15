#package Net::Whois::RedIRIS::Config;

# Modo Debug = 1. Poner 0 en caso que la ejecución sea normalSet ($_DEBUG_, 1);
Set ($_DEBUG_, 1);

# Para imprimir logs en demasía, poner $_DEBUG_ = 1 y $_VERBOSE_ = 1
# $_VERBOSE_ solo funciona si el modo debug está activado 
Set ($_VERBOSE_, 1);

# Fichero sobre el que se escriben los logs
Set ($_LOGFILE_,'/var/log/modulo.log');

# Puerto de escucha del socket
Set ($_LISTENONPORT_, '43333');

# Parametros de configuración de MySQL
Set ($MySQLInfo,[
        'ranges' => [
                'Host' => 'bbdd.rediris.es',
                'Database' => 'NOCData',
		'Port' => '3306',
                'TableName' => 'rangosred',
                'User' => 'nocuser',
                'Password' => 'Ch1nd3nv1nto',
        ],
        ],
);

# Parametros de configuración y búsqueda de LDAP
Set ($LDAPInfo,[
        'institution' => [
                'Host' => 'magnesio.rediris.es',
                'Port' => '389',
		'TimeOut' => 10,
                'BindDN' => 'cn=whoisclient,dc=apu,dc=rediris,dc=es',
                'BindPassword' => 'whois.client.666',
                'BaseDN' => 'dc=com,dc=rediris,dc=es',
                'Filter' => '(schacPersonalUniqueID=urn:mace:terena.org:schac:personalUniqueID:es:copa:VALUE_DATA)',
        ],
        'irisPerson' => [
                'Host' => 'magnesio.rediris.es',
                'Port' => '389',
                'TimeOut' => 10,
                'BindDN' => 'cn=whoisclient,dc=apu,dc=rediris,dc=es',
                'BindPassword' => 'whois.client.666',
                'BaseDN' => 'dc=rotw,dc=rediris,dc=es',
                'Filter' => '&(schacUserStatus=urn:mace:terena.org:schac:userStatus:es:rediris.es:affiliation:organization:VALUE_DATA)(|(schacUserStatus=urn:mace:terena.org:schac:userStatus:es:rediris.es:affiliation:role:techcontact)(schacUserStatus=urn:mace:terena.org:schac:userStatus:es:rediris.es:affiliation:role:pcs)(schacUserStatus=urn:mace:terena.org:schac:userStatus:es:rediris.es:affiliation:role:pec))',
        ],
#        'certPerson' => [
#                'Host' => 'magnesio.rediris.es',
#                'Port' => '1389',
#                'TimeOut' => 10,
#                'BindDN' => 'uid=manager,dc=cert,dc=coord,dc=rediris,dc=es',
#                'BindPassword' => 'manag3rc3rt',
#                'BaseDN' => 'dc=cert,dc=coord,dc=rediris,dc=es',
#                'Filter' => '(o=VALUE_DATA)',
#        ],
        'domain' => [
                'Host' => 'magnesio.rediris.es',
                'Port' => '389',
                'TimeOut' => 10,
                'BindDN' => 'cn=whoisclient,dc=apu,dc=rediris,dc=es',
                'BindPassword' => 'whois.client.666',
                'BaseDN' => 'dc=com,dc=rediris,dc=es',
                'Filter' => '(associatedDomain=VALUE_DATA)',
        ],
        'ipdomain' => [
                'Host' => 'magnesio.rediris.es',
                'Port' => '389',
                'TimeOut' => 10,
                'BindDN' => 'cn=whoisclient,dc=apu,dc=rediris,dc=es',
                'BindPassword' => 'whois.client.666',
                'BaseDN' => 'dc=whois,dc=rediris,dc=es',
                'Filter' => '(irisClassifCode=urn:mace:rediris.es:classif:organization:VALUE_DATA)',
        ],
        ],
);



1;
