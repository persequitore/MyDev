# INFORMACIÓN DEL PROGRAMA
# ---------------------------
# 
#       La información y ayuda se encuentra en el ejecutable del programa principal
#	Vease "motor.pl"
#
# 
# COPYRIGHT
# -----------
#  '/var/log/whois.log'
#       This software is Copyright (c):
#               - Carlos Fuente Bermejo - carlos.fuentes@rediris.es
#               - David Rodriguez Galiano - david.rodriguez@soporte.rediris.es 
# 

package Net::Whois::RedIRIS::Config; 
use strict;
use vars qw($VERSION);
$VERSION = '6.000';
######################################################################
# Constructor de la clase
sub new {
	my $this = shift; #Cogemos la clase que somos o una referencia a la clase (si soy un objeto)
	my $class = ref($this) || $this; #Averiguo la clase a la que pertenezco

	my $self={}; 				# Inicializamos la tabla hash que contendrá las var. de instancia
        bless ($self, $class);                    # Perl nos tiene que dar el visto bueno (bendecirla)
	$self->_Init(@_);

	return $self; 			# Devolvemos la clase recién construida
}

######################################################################
# Inicializa el objeto que almacena la configuración
sub _Init {

	my $this = shift;
  	my %args = ( 	LogFile => undef,
               		ConfigFile => undef,
               @_ );


	( defined $args{LogFile} ) ? $this->{'_LOGFILE_'} = $args{LogFile}:$this->{'_LOGFILE_'} =  '/var/log/whois.log';
	( defined $args{ConfigFile} ) ? $this->{'_CONFIGFILE_'} = $args{ConfigFile} : $this->{'_CONFIGFILE_'} = '/etc/sobreiris/config_modulo.pm';

	# Leemos la configuracion del fichero de configuracion
	if ($this->loadConfig() == -1){
		my $message = "No se ha podido cargar el fichero de configuración ".$this->{'_CONFIGFILE_'}."\n";
		$message .= "Fichero de logs: ".$this->{'_LOGFILE_'};
		print $message;
		if (open LOGFILE,>>$this->{'_LOGFILE_'}) {
                	print LOGFILE scalar localtime(time)." $message\n";
                	close LOGFILE;
        	}
		exit (-1);
	}
		
        # Fichero de logs
	if ($Net::Whois::RedIRIS::Config::_LOGFILE_)  {
                $this->{'_LOGFILE_'} = $Net::Whois::RedIRIS::Config::_LOGFILE_;
        }

        # Modo debug
        if ($Net::Whois::RedIRIS::Config::_DEBUG_) {
                $this->{'_DEBUG_'} = $Net::Whois::RedIRIS::Config::_DEBUG_;
        }
	else{
                $this->{'_DEBUG_'} = 0;
	}

        # Modo verbose
        if ($Net::Whois::RedIRIS::Config::_VERBOSE_) {
                $this->{'_VERBOSE_'} = $Net::Whois::RedIRIS::Config::_VERBOSE_;
        }
	else{
                $this->{'_VERBOSE_'} = 0;
	}

        # Puerto de escucha
        if ($Net::Whois::RedIRIS::Config::_LISTENONPORT_) {
                $this->{'_LISTENONPORT_'} = $Net::Whois::RedIRIS::Config::_LISTENONPORT_;
        }
	else{
                $this->{'_LISTENONPORT_'} = 4343;
	}

	# Parámetros de configuración y conexión de MySQL
	my @dataConfig = @{$Net::Whois::RedIRIS::Config::MySQLInfo};

        # Bucle para meter en un hash los parametros de configuracion que se encuentran en el array cargado por la funcion Load
        for (my $i=0; $i < scalar(@{$dataConfig[1]}); $i=$i+2){
                $this->{'MySQL'}->{$dataConfig[1]->[$i]} = $dataConfig[1]->[$i+1];
        }

	# Parámetros de configuración y conexión a LDAP
        @dataConfig = @{$Net::Whois::RedIRIS::Config::LDAPInfo};

        # Completamos una referencia a un hash en el que se incluyen todos los parámetros de configuración de LDAP
        # En la linea que se encuentra comentada se puede visualizar la lógica de cómo se están leyendo los parámetros
        # de configuración del fichero

        for (my $i=0; $i < scalar(@dataConfig); $i=$i+2){
                for (my $j=0; $j < scalar(@{$dataConfig[$i+1]}); $j=$j+2){
                        $this->{'LDAP'}->{$dataConfig[$i]}->{$dataConfig[$i+1]->[$j]} = $dataConfig[$i+1]->[$j+1] ;
                }
        }
}

######################################################################
# Métodos de acceso a los datos de la clase
#

######################################################################
# Método para cambiar o visualizar el modo debug
sub debug{
       my $self=shift; #El primer parámetro de un metodo es la  clase
 
       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'_DEBUG_'}=shift if (@_);

       #Devolvemos el nombre
       return $self->{'_DEBUG_'};
}


######################################################################
# Método para cambiar o visualizar el modo verbose
sub verbose{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'_VERBOSE_'}=shift if (@_);

       #Devolvemos el nombre
       return $self->{'_VERBOSE_'};
}


######################################################################
# Cambia o visualiza el fichero de logs
sub logFile{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'_LOGFILE_'}=shift if (@_);

       #Devolvemos el nombre
       return $self->{'_LOGFILE_'};
}


######################################################################
# Cambia o visualiza el puerto de escucha del demonio
sub listenOnPort{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'_LISTENONPORT_'}=shift if (@_);

       #Devolvemos el nombre
       return $self->{'_LISTENONPORT_'};
}


######################################################################
# Cambia o muestra el host de MySQL
sub MySQLHost{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'MySQL'}->{'Host'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'MySQL'}->{'Host'};
}


######################################################################
# Cambia o muestra la base de datos de MySQL
sub MySQLDatabase{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'MySQL'}->{'Database'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'MySQL'}->{'Database'};
}


######################################################################
# Cambia o muestra el puerto de conexion de MySQL
sub MySQLPort{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'MySQL'}->{'Port'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'MySQL'}->{'Port'};
}


######################################################################
# Cambia o muestra la tabla sobre la que se realizaran consultas de MySQL
sub MySQLTableName{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'MySQL'}->{'TableName'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'MySQL'}->{'TableName'};
}


######################################################################
# Cambia o muestra el usuario de MySQL
sub MySQLUser{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'MySQL'}->{'User'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'MySQL'}->{'User'};
}


######################################################################
# Cambia o muestra el password de MySQL
sub MySQLPassword{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'MySQL'}->{'Password'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'MySQL'}->{'Password'};
}


######################################################################
# Cambia o muestra el host de LDAP para las instituciones
sub LDAPHost_Institution{
       my $self=shift; #El primer parámetro de un metodo es la  clase
	
       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'institution'}->{'Host'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'institution'}->{'Host'};
}


######################################################################
# Cambia o muestra el puerto de conexión de LDAP para las instituciones
sub LDAPPort_Institution{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'institution'}->{'Port'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'institution'}->{'Port'};
}


######################################################################
# Cambia o muestra el time out de LDAP para las instituciones
sub LDAPTimeOut_Institution{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'institution'}->{'TimeOut'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'institution'}->{'TimeOut'};
}


######################################################################
# Cambia o muestra el BindDN de LDAP para las instituciones
sub LDAPBindDN_Institution{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'institution'}->{'BindDN'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'institution'}->{'BindDN'};
}


######################################################################
# Cambia o muestra la password de LDAP para las instituciones
sub LDAPBindPassword_Institution{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'institution'}->{'BindPassword'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'institution'}->{'BindPassword'};
}


######################################################################
# Cambia o muestra la BaseDN de LDAP para las instituciones
sub LDAPBaseDN_Institution{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'institution'}->{'BaseDN'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'institution'}->{'BaseDN'};
}


######################################################################
# Cambia o muestra el filtro de LDAP para las instituciones
sub LDAPFilter_Institution{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'institution'}->{'Filter'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'institution'}->{'Filter'};
}


######################################################################
# Cambia o muestra el host de LDAP para los puntos de contacto
sub LDAPHost_IRISPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'irisPerson'}->{'Host'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'irisPerson'}->{'Host'};
}


######################################################################
# Cambia o muestra el puerto de conexión de LDAP para los puntos de contacto
sub LDAPPort_IRISPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'irisPerson'}->{'Port'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'irisPerson'}->{'Port'};
}


######################################################################
# Cambia o muestra el time out de LDAP para los puntos de contacto
sub LDAPTimeOut_IRISPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'irisPerson'}->{'TimeOut'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'irisPerson'}->{'TimeOut'};
}


######################################################################
# Cambia o muestra el BindDN de LDAP para los puntos de contacto
sub LDAPBindDN_IRISPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'irisPerson'}->{'BindDN'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'irisPerson'}->{'BindDN'};
}


######################################################################
# Cambia o muestra la password de LDAP para los puntos de contacto
sub LDAPBindPassword_IRISPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'irisPerson'}->{'BindPassword'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'irisPerson'}->{'BindPassword'};
}


######################################################################
# Cambia o muestra la BaseDN de LDAP para los puntos de contacto
sub LDAPBaseDN_IRISPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'irisPerson'}->{'BaseDN'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'irisPerson'}->{'BaseDN'};
}


######################################################################
# Cambia o muestra el filtro de LDAP para los puntos de contacto
sub LDAPFilter_IRISPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'irisPerson'}->{'Filter'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'irisPerson'}->{'Filter'};
}


######################################################################
# Cambia o muestra el host de LDAP para los contactos de seguridad
sub LDAPHost_CERTPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'certPerson'}->{'Host'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'certPerson'}->{'Host'};
}


######################################################################
# Cambia o muestra el puerto de conexión de LDAP para los contactos de seguridad
sub LDAPPort_CERTPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'certPerson'}->{'Port'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'certPerson'}->{'Port'};
}


######################################################################
# Cambia o muestra el time out de LDAP para los contactos de seguridad
sub LDAPTimeOut_CERTPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'certPerson'}->{'TimeOut'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'certPerson'}->{'TimeOut'};
}


######################################################################
# Cambia o muestra el BindDN de LDAP para los contactos de seguridad
sub LDAPBindDN_CERTPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'certPerson'}->{'BindDN'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'certPerson'}->{'BindDN'};
}


######################################################################
# Cambia o muestra la password de LDAP para los contactos de seguridad
sub LDAPBindPassword_CERTPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'certPerson'}->{'BindPassword'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'certPerson'}->{'BindPassword'};
}


######################################################################
# Cambia o muestra la BaseDN de LDAP para los contactos de seguridad
sub LDAPBaseDN_CERTPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'certPerson'}->{'BaseDN'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'certPerson'}->{'BaseDN'};
}


######################################################################
# Cambia o muestra el filtro de LDAP para los contactos de seguridad
sub LDAPFilter_CERTPerson{
       my $self=shift; #El primer parámetro de un metodo es la  clase

       #Miramos si se le ha pasado algún parámetro, en cuyo caso será el nombre
       $self->{'LDAP'}->{'certPerson'}->{'Filter'} = shift if (@_);

       #Devolvemos el nombre
       return $self->{'LDAP'}->{'certPerson'}->{'Filter'};
}


######################################################################
# Destructor del objeto
sub destroy {
	my $self=shift; #El primer parámetro de un metodo es la  clase
        
	delete ($self->{'_LOGFILE_'});
	delete ($self->{'_DEBUG_'});  
        delete ($self->{'_VERBOSE_'});
	delete ($self->{'_LISTENONPORT_'});
	delete ($self->{'MySQL'});
	delete ($self->{'LDAP'}); 
}


###########################################################################################
# Escribe un mensaje en el fichero de logs
sub writeLog {
	my $self = shift;
        my ($message) = @_;

	if ($self->{'_LOGFILE_'}){
        	if (open LOGFILE,">>$self->{'_LOGFILE_'}") {
                	print LOGFILE scalar localtime(time)." $message\n";
                	close LOGFILE;
        	}
	}
	else{
		if (open LOGFILE,">>$self->{'_LOGFILE_'}") {
                        print LOGFILE scalar localtime(time)." $message\n";
                        close LOGFILE;
                }
	}
}


######################################################################
# Lee y carga el fichero de configuracion
sub loadConfig { 
   my $self = shift;
   local *Set = sub { $_[0] = $_[1] unless defined $_[0] };
   use File::Basename;
   my $path = dirname($self->{'_CONFIGFILE_'});
   my @filepaths;
   push @filepaths, $path, @INC;
   local @INC = @filepaths;
   require $self->{'_CONFIGFILE_'} || die return (-1);
}


1;
