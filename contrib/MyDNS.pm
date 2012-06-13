## MyDNS.pm
##
#
#  A object based interface to the mydns DB information
#
#  Originally coded by Allen Bettilyon ( allen@bettilyon.net )
#
#
#  Quick and dirty usage syntax: 
#
#   
#    $mydns = MyDNS->new( @YOUR_DBH_CONNECT_OPTIONS );
#
#    $record_hash = {
#                     'origin' => 'yoursite.com.',
#                     'name'   => 'www',
#                     'type'   => 'A',
#                     'data'   => '127.0.0.1',
#    }; 
# 
#    $soa_hahs = {
#		   'origin'  => 'yoursite.com.'.
#		   'ns'      => 'ns1.yoursite.com.',
#    };
#
#
# 
#    $rval = $mydns->put_rr( $record_hash );
#    $rval = $mydns->drop_rr( $record_hash );
#
#    unless( $rval ){ print "$mydns->{error}\n"; }
#
#
#    $soa_hash_ref = $mydns->get_soa( $origin );
#              
#    $rr_array_ref = $mydns->get_all_rr( $origin );
#
#
#    **  $rr_array_ref is an array of hashes.  The hashes are formated like
#        the $record_hash shown above 
# 
#    **  The soa hash can be passed all the soa options, but assums 
#        fairly standard defaults if nothing is given (see DEFAULT values) 


package MyDNS;

use DBI;

##########################################
# Set some DEFAULT values for 

$mbox_prefix	= "dns";
$soa_refresh	= 28800;
$soa_retry	= 7200;
$soa_expire	= 604800;
$soa_minimum	= 86400;
$soa_ttl	= 86400;
$rr_ttl		= 86400;

#########################################

1;

sub new {
   my $type = shift;
   my $class = ref($type) || $type || _PACKAGE_;
   my @connect_array = @_;

   my %o = ();

   ##
   ## Make our DBI connection  
   ##
   $o{dbh} = DBI->connect( @connect_array ) ; 


   ##
   ## PreDeclare all the SQL queries
   ## 
   $o{get_soa_query} = $o{dbh}->prepare(qq{
	SELECT * FROM soa WHERE origin = ?
   });

   $o{get_all_rr_query} = $o{dbh}->prepare(qq{
	SELECT name,type,data,aux,rr.ttl 
	FROM rr,soa 
	WHERE soa.id = rr.zone and soa.origin = ? 
	ORDER BY name,type,data
   });

   $o{get_soa_id} = $o{dbh}->prepare(qq{
	SELECT id FROM soa WHERE origin = ?
   });
   
   ## prepare our insert/replace queries
   $o{put_soa_query} = $o{dbh}->prepare(qq{
	INSERT IGNORE INTO 
	  soa (origin,ns,mbox,serial,refresh,retry,expire,minimum,ttl) 
	  VALUES (?,?,?,?,?,?,?,?,?)
   });

   $o{update_soa_query} = $o{dbh}->prepare(qq{
	UPDATE soa 
 	  set ns=?,mbox=?,serial=?,refresh=?,retry=?,expire=?,minimum=?,ttl=? 
	WHERE origin = ?
   });


   $o{get_serial_query} = $o{dbh}->prepare(qq{
	SELECT serial FROM soa WHERE origin = ?
   });

   $o{update_serial_query} = $o{dbh}->prepare(qq{
	UPDATE soa set serial = ? WHERE origin = ?
   });

   $o{drop_rr_query} = $o{dbh}->prepare(qq{
	DELETE FROM rr 
	WHERE zone=? and name = ? and type = ? and data = ?
   });

   $o{put_mx_query} = $o{dbh}->prepare(qq{
	REPLACE INTO 
	  rr (zone,name,type,aux,data,ttl) 
	  VALUES ( ?,?,?,?,?,?)
   });
  
   $o{put_mx_query_noName} = $o{dbh}->prepare(qq{
	REPLACE INTO 
	  rr (zone,type,aux,data,ttl) 
	VALUES ( ?,?,?,?,?)
   });  

   $o{put_rr_query} = $o{dbh}->prepare(qq{
	REPLACE INTO 
	  rr (zone,name,type,data,ttl) 
	VALUES (?,?,?,?,?)
   });

   $o{put_rr_query_noName} = $o{dbh}->prepare(qq{
	REPLACE INTO 
	  rr (zone,type,data,ttl) 
	VALUES (?,?,?,?)
   });

			
   bless \%o, $class;
}


sub get_soa {
    my $self = shift;
    my $site = shift;

    unless( $site =~ /\.$/ ){ $site .= "."; }

    $self->{get_soa_query}->execute( $site );
    my ($id,$origin,$ns,$mbox,$serial,$refresh,$retry,$expire,$minimum,$ttl) 
	= $self->{get_soa_query}->fetchrow_array;

    unless( $id and $id =~ /\d+/ ){
	return undef;
    }
    
    my %rval = (
		'id'=>$id,
		'origin'=>$origin,
		'ns'=>$ns,
		'mbox'=>$mbox,
		'serial'=>$serial,
		'refresh'=>$refresh,
		'retry'=>$retry,
		'expire'=>$expire,
		'minimum'=>$minimum,
		'ttl'=>$ttl,
		);

    return \%rval;

}

sub get_all_rr {
    my $self = shift;
    my $site = shift;

    my @rval = [];
    my $count = 0;

    ## make sure we end in a "."!!
    unless( $site =~ /\.$/ ){ $site .= "."; }

    $self->{get_all_rr_query}->execute( $site );
    while( my( $name,$type,$data,$aux,$ttl ) = $self->{get_all_rr_query}->fetchrow_array ){
	$rval[$count++] = {
		    'name'=>$name,
		    'type'=>$type,
		    'data'=>$data,
		    'aux'=>$aux,
		    'ttl'=>$ttl,
		};
    }


    return \@rval;
}

sub get_rr {
    print "get_rr not implimented\n";
}

sub put_soa {
    my $self = shift;
    my $hash = shift;

    ## check the sanity of our input!
    ##################################

    ## origin is required!  also ensure it ends with a "."
    unless( length( $hash->{origin} ) ){
	warn  "ERROR: No 'origin' specified\n";
	$self->{error} = "No origin\n";
	return undef;
    }
    unless( $hash->{origin} =~ /\.$/ ){ $hash->{origin} .= "."; }	    


    ## ns is requried!!!  print error and return undef;
    unless( $hash->{ns} =~ /[\w\d\.]+/ ){
	warn "ERROR: invalid 'ns' value";
	$self->{error} = "Invalid ns value";
	return undef;
    }
    unless( $hash->{ns} =~ /\.$/ ){ $hash->{ns} .= "."; }	    


    ## mbox
    ## 
    ## if none specified or in wrong fromat.. generate a sane default
    unless( $hash->{mbox} and $hash->{mbox} =~ /[\w\d]+\.[\w\d\.]+/ ){
	$hash->{mbox} = "$mbox_prefix." . $hash->{origin};
    }

    ## serial
    unless( $hash->{serial} and  $hash->{serial} = /\d+/ ){ 
	$hash->{serial} = $self->get_new_serial; 
    }
    
    ## refresh
    unless( $hash->{refresh} and $hash->{refresh} =~ /\d+/ ){ 
	$hash->{refresh} = $soa_refresh; 
    }

    ## retry
    unless( $hash->{retry} and $hash->{retry} =~ /\d+/ ){ 
	$hash->{retry} = $soa_retry; 
    }					

    ## expire
    unless( $hash->{expire} and $hash->{expire} =~ /\d+/ ){ 
	$hash->{expire} = $soa_expire; 
    }

    ## minimum
    unless( $hash->{minimum} and $hash->{minimum} =~ /\d+/ ){ 
	$hash->{minimum} = $soa_minimum; 
    }

    ## ttl
    unless( $hash->{ttl} and $hash->{ttl} =~ /\d+/ ){ 
	$hash->{ttl} = $soa_ttl; 
    }


    ##
    ## Should now have sane (valid) values for this soa, lets add the puppy!
    ##
    my $rval = $self->{put_soa_query}->execute(
				    $hash->{origin},
				    $hash->{ns},
				    $hash->{mbox},
				    $hash->{serial},
				    $hash->{refresh},
				    $hash->{retry},
				    $hash->{expire},
				    $hash->{minimum},
				    $hash->{ttl}
				    );

    
    unless( $rval == 1 ){
	## looks like there was an issue... lets try the update
	$rval = $self->{update_soa_query}->execute(
						   $hash->{ns},
						   $hash->{mbox},
						   $hash->{serial},
						   $hash->{refresh},
						   $hash->{retry},
						   $hash->{expire},
						   $hash->{minimum},
						   $hash->{ttl},
						   $hash->{origin}
						   );
    }
    return $rval;
}

sub put_rr {
    my $self = shift;
    my $hash = shift;

    ## Check the sanity of the input vars

    ## origin... 
    unless( length($hash->{origin}) ){
	warn "ERROR: need to specifiy an 'origin'!\n";
	$self->{error} = "Need to specify an origin";
	return undef;
    }
    unless( $hash->{origin} =~ /\.$/ ) { $hash->{origin} .= "."; }

    ## name
    unless(   $hash->{name} =~ /[\w\d\.\-]/ 
	or $hash->{name} eq ''
	or $hash->{name} eq '*'
	){
	warn "ERROR: need to specificy a valid 'name'!\n";
	$self->{error} = "Meed to specify a name\n";
	return undef;
    }

    ## type
    unless( $hash->{type} =~ /^(A|AAAA|CNAME|MX|NS|TXT)$/i ) {
	warn "ERROR: $hash->{type} is an invalid 'type'!\n";
	$self->{error} = "$hash->{type} is an invalid type";
	return undef;
    }

    ## data
    ############ A records
    if( $hash->{type} =~ /^(A|AAAA)$/ ){ ## must be an ip address
	unless( $hash->{data} =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ ){
	    warn "ERROR: $hash->{type} records must have 'data' that matches an ip address!\n";
	    $self->{error} = "Data is not a valid ip address";
	    return undef;
	}
    }
    ############ CNAMES and NS
    elsif( $hash->{type} =~ /^(CNAME|NS)$/ ){
	unless( $hash->{data} =~ /[\w\d]+\.[\w\d\.]+$/ ){
	    warn "ERROR: $hash->{type} record appears to be invaled!\n";
	    $self->{error} = "Data is invalid for $hash->{type} records";
            return undef;
	}
	## also ensure ther is a "." on the end 
	unless( $hash->{data} =~ /\.$/ ){ $hash->{data} .= "."; }
    }
    ############ MX
    elsif( $hash->{type} =~ /^MX$/ ){
	## ensure we've got a dot on the end
	unless( $hash->{data} =~ /\.$/ ){ $hash->{data} .= "."; }

	## gotta yank the auxilary section off
	my $old_data = $hash->{data}; 
	unless( ($hash->{aux},$hash->{data}) = $hash->{data} =~ /([\d]+)\s+([\w\d\.\-]+\.)$/ ){
	    warn "ERROR: MX record appears to be invalid!\n";
	    warn " data is: $hash->{data}\n";

	    $self->{error} = "MX record is invalid, make sure a priority is specified! (bad data was: $old_data)";	

	    return undef;
	}

    }
    ## TXT records
    elsif( $hash->{type} =~ /^TXT$/ ){
        ## make sure there is SOME data
        unless( length( $hash->{data} ) ){
            warn "ERROR: TXT records must have SOME data!\n";
	    $self->{error} = "TXT record has NO data!\n";
            return undef;
        }
    }

    ## ttl
    unless( $hash->{ttl} and $hash->{ttl} =~ /\d+/ ){ 
	$hash->{ttl} = $rr_ttl; }

    ##
    ## All data should be verified by now...
    ########################################### 
   
    
 
    ## get the id that matches to the propper soa table
    $self->{get_soa_id}->execute( $hash->{origin} );
    my( $zone_id ) = $self->{get_soa_id}->fetchrow_array;

    my $rval = undef;

    ###
    ### IF WE HAVE A NAME, otherwise..
    ###
    if( $hash->{name} and length( $hash->{name} ) ){
       if( $hash->{type} =~ /mx/i ){
           $rval = $self->{put_mx_query}->execute(
				$zone_id,
				$hash->{name},
				$hash->{type},
				$hash->{aux},
				$hash->{data},
				$hash->{ttl}
		);
       } else {
          $rval = $self->{put_rr_query}->execute(
				$zone_id,
				$hash->{name},
				$hash->{type},
				$hash->{data},
				$hash->{ttl}
		);
       }    
    }
    else {
      ##
      ## We got no name... use differnet sql handles
      ##
      if( $hash->{type} =~ /mx/i ){
           $rval = $self->{put_mx_query_noName}->execute(
                                $zone_id,
                                $hash->{type},
                                $hash->{aux},
                                $hash->{data},
                                $hash->{ttl}
                );
      } else {
          $rval = $self->{put_rr_query_noName}->execute(
				$zone_id,
                                $hash->{type},
                                $hash->{data},
                                $hash->{ttl}
                );
       }
    }

    $self->update_serial( $hash->{origin} ); 

    return $rval;
}

sub update_serial {
    my $self = shift;
    my $site = shift;

    unless( $site =~ /\.$/ ){ $site .= "."; }


    $self->{get_serial_query}->execute( $site ); 
    my( $cur_serial ) = $self->{get_serial_query}->fetchrow_array;

    my $new_serial = $self->get_new_serial;

    ##
    ## Make sure new serial is greater than the old one
    ##
    unless( $new_serial > $cur_serial ){
       $new_serial = $cur_serial + 1;
    }


    my $rval = $self->{update_serial_query}->execute( $new_serial, $site );

    return $rval;
}

sub get_new_serial {
    ## generate and return a new serial nubmer based on 'NOW!'

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time); 
    $mon = "0" . $mon if $mon < 10;
    $hour = "0" . $mon if $hour < 10;
    return $year+1900 . $mon . $mday . $hour;
}


sub drop_rr {
    my $self = shift;
    my $hash = shift;

    unless( length($hash->{origin})){ 
	warn "WARNING: Need an 'origin' to drop\n";
	$self->{error} = "No origin";
        return undef;
    }
    unless( $hash->{type} =~ /^(A|AAAA|CNAME|MX|NS|TXT)$/i ){
	warn "WARNING: Need a valid 'type' to drop\n";
	$self->{error} = "No valid type";
        return undef;
    }
    unless( length($hash->{data}) ){
	warn "WARNING: Need valid 'data' to drop\n";
	$self->{error} = "Need valid data";
        return undef;
    }

    unless( $hash->{origin} =~ /\.$/ ){ $hash->{origin} .= "."; }    

    unless( length($hash->{name})){
	## make sure name at least exists	
	$hash->{name} = "";
    }

    ## get the zone_id
    $self->{get_soa_id}->execute( $hash->{origin} );
    my($zone_id) = $self->{get_soa_id}->fetchrow_array;

    my $rval = $self->{drop_rr_query}->execute( $zone_id, $hash->{name}, $hash->{type}, $hash->{data} );


    $self->update_serial( $hash->{origin} );
    
    return $rval;
}
    




