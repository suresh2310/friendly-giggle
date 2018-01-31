# encoding: utf-8
#
# Copyright 2018, Suresh D
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
#
#
#
# Unless required by applicable law or agreed to in writing,software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#author : Suresh D
#The File can be viewed under github using the link https://github.com/suresh2310/friendly-giggle
#
##Testing MariaDB on Ubuntu
if ( os[:name]== 'ubuntu' && os[:family]=='debian' && os[:release]=='17.04' )
	#to check MariaDB is installed,enabled and running
	control 'os-ubuntu' do
	impact 0.5
	title 'MariaDB installed'
	desc 'MariaDB service should be installed,enabled and running'
	describe service('mariadb') do
		it {should be_installed}
		it {should be_enabled}
		it {should be_running}
	end
	describe command('mysql -V') do
		its('stdout') { should eq  "mysql  Ver 15.1 Distrib 10.2.12-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2\n" }

	end
	end
	
	#MariaDB file check
	control 'MariaDB-file-check' do
	desc 'Mariadb.conf should exist and Mariadb.Service should be a file'
	describe file('/etc/mysql/conf.d/mariadb.cnf') do
		it { should exist }
		it { should be_file }
		its('mode') { should cmp '0644' } 
	end
	describe file('/lib/systemd/system/mariadb.service') do
		it { should exist }
		it { should be_file }
	end
	end
	#MariaDB_service file contents and permissions
	control 'mariadb-service' do
	title 'Verify mariadb.service file'
	desc 'The Mariadb service file should contain the path to mariadb.conf file ant it should be owned by root and only be writable by 		others and readable by others'
	describe file('/lib/systemd/system/mariadb.service') do
		it { should be_owned_by 'root' }
		it { should be_grouped_into 'root' }
		it { should be_readable.by('others') }
		it { should_not be_writable.by('others') }
		it { should_not be_executable.by('others') }
	end
	describe file('/lib/systemd/system/mariadb.service') do
		its('content') { should match 'User=mysql' }
	        its('content') { should match 'Group=mysql' }
                its('content') { should match 'ExecStartPre=/usr/bin/mysql_install_db -u mysql'}
	end
	end	
	#MariaDB port and ip
	control 'MariaDB-server' do
	impact 0.8
	title 'MariaDB port and ip'
	desc 'The MariaDB port and ipaddress'
	describe port('3306') do
		it { should be_listening }
		its('processes') { should include 'sql'}
		its ('protocols') { should include 'tcp' }
	end
	describe host('127.0.0.1', port: 3304, protocol: 'tcp') do
	  	it { should be_resolvable }
	  	its('ipaddress') { should cmp '127.0.0.1' }
	end
	end
	
	#check permissions of MariaDB config file
	  control 'MariaDB-conf' do
	  impact 1.0
	  title 'Checking MariaDB config file owner, group and permissions'
	  desc 'The MariaDB config file should owned by root, only be writable by owner and readable by others.'
	  describe file('/etc/mysql/conf.d/mariadb.cnf') do
		it { should be_owned_by 'root' }
		it { should be_grouped_into 'root' }
		it { should be_readable.by('others') }
		it { should_not be_writable.by('others') }
		it { should_not be_executable.by('others') }
	end
	end
	#process security
	control 'Mariadb-process' do
	impact 0.7
	title 'Process-security'
	desc 'MariaDB process should not run as the root user'
	describe processes('mariadb') do
		its('users') { should_not include 'root' }
	end
	end
	
	#to check about the user
	control 'user' do
	desc 'The MariaDB profiles for a single, known/expected local user, including the groups to which that user belongs, the frequency of 		required password changes, and the directory paths to home and shell'
	describe user('mariadb') do
		it { should exist }
		its('group') {should_not eq 'root' }
	end
	end
	#to check info of MariaDB
	#fetching uid and gid of a system
	File.open('/etc/passwd').each do |line|
		if line.include? "mariadb"
			user=line
			userdata=user.split(":")
			user_uid=userdata[2]
			user_gid=userdata[3]
			control 'passwd' do
			title 'Mariadb-info'
			desc 'It contains the MariaDB information that may log into the system'
			if(describe passwd()do
			  its('users') { should include 'mariadb' }
			 end)
			describe passwd.users('mariadb') do
				its('uids') { should include user_uid }
				its('gids') { should include user_gid }
			end
			end
			end
		end
	end
	#Comparing user with their uids
	control 'mariadb-process' do
	desc 'Creating user of MariaDB and comparing with their Uids'
	describe passwd.where { user == 'mariadb' } do
  		its('uids') { should cmp 1001 }
  		its('count') { should eq 1 }
	end
	describe passwd.uids(1001) do
		its('users'){ should cmp 'mariadb' }
  		its('count'){ should eq 1 }
	end 
	end
	
	#Checking that the bash shell contains the user MariaDB
	control 'Bash Shell'do
	desc 'Creating user MariaDB and checking whether it found under bash or not' 
	describe passwd.shells('/bin/bash') do
  		its('users') { should include 'mariadb' }
	end
	end
	 control 'mariadb-security-ssl' do
	 title 'SSL is enabled'
	 desc 'Enabling SSL ensures communication to mariadb is secure'
	 impact 0.6 
	#security enhancement
=begin
		# The ssl can be enabled in mariadb by adding the below line of codes in /etc/mysql/my.cnf
	 security:
	   clusterAuthMode: x509
	 net:
	   ssl:
		  mode: requireSSL
		  PEMKeyFile: <path to TLS/SSL certificate and key PEM file>
		  CAFile: <path to root CA PEM file>
=end
	 describe ssl(port:3306) do
  	   	it { should be_enabled }
	  end
	 describe x509_certificate('/etc/mysql/ssl/ca-cert.pem')do
	  	its('subject.CN') { should eq "MariaDb admin"}
	  	its('issuer_dn') { should match "CN=MariaDb admin"}
	  	its('version') { should eq 2 }
	  	its('signature_algorithm') { should eq 'sha256WithRSAEncryption' }
	  	its('key_length') { should be 2048 }
	  	its('validity_in_days') { should be > 20 }
	  	#its('not_before') { should eq '2018-01-18 12:01:01.000000000 +0000' }
  	  	#its('not_after')  { should eq '3017-05-21 12:01:01.000000000 +0000' }
	  	its('serial') { should eq 11561971667712227939 }
	  
	 end
	describe parse_config_file('/etc/mysql/my.cnf') do
		its('mysqld.mode') { should eq 'requireSSL' }
		its('mysqld.PEMKeyFile') { should_not be_nil }
	 end
	end
	#checking Pid and socket file exist
	control 'MariaDB-Pid' do
	desc 'Check Pid and socket should be a file and it should exist'
	describe file('/var/run/mysqld/mysqld.pid') do
		it { should exist }
	end 
	describe file('/var/run/mysqld/mysqld.sock') do
		it { should exist }
	end
	end
	#Disable local-infile
	 
	control 'Local-infile' do 
	desc 'disabling local_infile to prevent access to the underlying filesystem within mysql'
	describe mysql_conf do
		its('mysqld.local-infile'){ should be '0'} # disabling local-infile gives protection to our filesystem
	end
	end
	#Changing port and enabling mysql logging
	control 'MariaDB-conf' do 
	title 'Port changing' 
	desc 'Changing the port and storing log file'
	describe mysql_conf do
		its('mysqld.port'){ should be '5000' } #The default port number is 3306 but you can change it under the [mysqld] section for 			security.
		its('mysqld.general_log_file'){ should eq '/var/log/mysql.log' } #We will know what happens on a server, in case of any attacks 		by enabling MYSQL logging. From MariaDB 10.0 use general_log instead of log.
		its('mysqld.log_tc_size') { should eq '24576' }  # size of the transaction log file
	end
	end

	#Performance tuning of MariaDB
	#innodb_buffer_pool_size should contain 60-70% 0f the memory to store caching data and indexes 
	
	control 'innodb-options' do 
	desc 'Checking innodb parameters'
	describe mysql_conf do
		its('mysqld.innodb_buffer_pool_size'){ should eq '1228M'}# enabling caching and indexing in MariaDB server by setting the 			InnoDB buffer pool size parameter
		its('mysqld.inodb_file_per_table') { should eq '1'}# we can store each InnoDB table and associated indexes in its own data file
		its('mysqld.innodb_log_compressed_pages') { should be 'OFF'}# Not images of recompressed pages are stored in the InnoDB redo 			logs	
		its('mysqld.innodb_use_atomic_writes') { should be '1'}# directly ask the filesystem to provide an atomic (all or nothing) 			write guarantee. We enable it by '1' or '0'
		its('mysqld.innodb_use_trim') { should be 'ON'}# Use trim to free up space of compressed blocks.
		its('mysqld.innodb_log_files_in_group') { should eq '2'} # no of physical files in the Innodb redo log
	end
	end
	#Query-cache value should not be more than 300M 
	control 'Query-Cache' do
	desc 'Checking size of Query-cache'
	describe mysql_conf do
		its('mysqld.query_cache_type'){should eq '1'}
		its('mysqld.query_cache_limit'){should eq '256K' }
		its('mysqld.query_cache_min_res_unit'){should eq '2k'}
		its('mysqld.query_cache_size'){should eq '64M'}# it caches all the queries which keep on repeating with same data
	end
	end
	#tmp_table_size should be 64M for every GB of Ram
	control 'Temp-table-size'do
	desc 'Checking the size of tmp_table_size and also equalizing the values of both tmp_table_size and max_heap_table_size to increase 		performance of database'
	describe mysql_conf do
		its('mysqld.tmp_table_size'){ should eq '64M' }    #to avoid disk writes on your server
		its('mysqld.max_heap_table_size'){ should eq '64M' }
	end
	end
	#Enabling mysql slow query logs
	control 'Query-logs' do
	desc 'Checking mysql slow-query-logs are enabled which are to determine issues with your database and to debug them'
	describe mysql_conf do
		its('mysqld.slow-query-log') { should eq '1'} # contains sql stmt to execute 
		its('mysqld.long_query_time') { should eq '1'} # max time to execute the query and it should be between 0 and 10
	end
	end 
	#Check mysql idle connection
	control 'wait-timeout' do
	desc ' checking wait-timeout default value is 28800sec'
	describe mysql_conf do
		its('mysqld.wait_timeout'){ should eq '28800'} #Idle time wait for connection and closed automatically after mentioned timeout
		its('mysqld.interactive_timeout'){ should eq '28800' }# the interval between user and the system
	end
	end 
	control 'max-allowed-packets' do
	desc 'checking whether max-allowed-packet is high and key_buffer_size is low'
	describe mysql_conf do
		its('mysqld.max_allowed_packet'){ should be > '128M' }
		its('mysqld.key_buffer_size'){should be > '' }
		its('mysqld.max_connect_errors') { should eq '100' }#Limit to the number of successive failed connects from a host before the 			host is blocked from making further connections.
		its('mysqld.max_error_count') { should eq '64' }#Specifies the maximum number of messages stored for display by SHOW ERRORS and 		SHOW WARNINGS statements.  
		its('mysqld.max_prepared_stmt_count') { should eq '16382' } #Maximum number of prepared statements on the server
		its('mysqld.max_recursive_iterations') { should eq '4294967295'}#Maximum number of iterations when executing recursive queries. 
		its('mysqld.max_sort_length') { should eq '1024'} #Maximum size in bytes used for sorting data values - anything exceeding this 		is ignored
	end 
	end
	
	control 'big-tables' do 
	desc 'Big-tables should be enabled and it saves all temporary sets to disc'
	describe mysql_conf do
		its('mysqld.big_tables') { should eq '1'}
		its('mysqld.character_set_client') {should eq 'utf8' }
		its('mysqld.character_set_filesystem') { should eq 'binary' }
		its('mysqld.connect_timeout'){ should eq '10' }
		its('mysqld.default_storage_engine') { should eq 'InnoDB'}
		its('mysqld.delayed_insert_timeout') { should eq '300' }
		its('mysqld.delayed_queue_size') { should eq '1000' }
		its('mysqld.userstat'){ should eq '1' } # It keeps several hash tables in memory, all variables are incremented while the query 		is running. At the end of each statement the global values are updated.
	end
	end
	#Minimum and Maximum word length
 
	control 'Word-length' do
	desc 'checking the minimum and maximum word length'
	describe parse_config_file('/etc/mysql/my.cnf') do
		its('sqld.ft_max_word_len'){ should eq '84' }# max word length of text
		its('sqld.ft_min_word_len') {should eq '4' } # min word length of text
	end
	end
	#setting in-transaction value to default '0'
	
	control  'in-transaction' do
	desc ' read-only variable that is set to 1 if you are in a transaction, and 0 if not'
	describe mysql_conf do
		its('mysqld.in_transaction') {should eq '0' }
	end
	end
	#locales  to identify error messages file

	control 'lc-messages' do 
	desc 'using locale to find the location of error messages and to determine the language used for date and time functions DAYNAME(), 		MONTHNAME() and DATE_FORMAT()'
	describe mysql_conf do
		its('lc_messages') { should eq 'en-us' } # to find the location of error messages
		its('lc_time_names') {should eq 'en_US' }# to determine the language used for date and time	
	end
	end
	#File system case sensitive or not
	
	control 'file-system' do 
	desc 'If set to OFF, file names are case-sensitive. If set to ON, they are not case-sensitive'
	describe mysql_conf do
		its('mysqld.lower_case_file_system') { should eq '##' }
		its('mysqld.lower_case_table_names') { should eq '0'} #table names and aliases and database names are compared in a 			case-ensitive manner if set to '0'
	end
	end
	control 'mariadb-conf' do
	title 'slave_net_timeout'   
	desc 'Checking slave_net_timeout is enabled and set to 60 sec '
	describe mysql_conf do
		its('mysqld.slave_net_timeout') { should eq '60' }#Time in seconds for the slave to wait for more data from the master before 			considering the connection broken 
		its('mysqld.slave_parallel_threads') { should eq '0' }# set to 0 (the default) parallel execution is disabled and the slave 			uses a single applier thread.  	
	end
	end
	control 'mariadb-conf' do
	describe mysql_conf do
		its('mysqld.innodb_deadlock_detect'){ should eq '1' }# the InnoDB deadlock detector is enabled
		its('mysqld.replicate_annotate_row_events') { should be 'ON' } # reproducing or adding notes to given explanation
	end
	end

	control 'recovery options' do
	desc ' using aria-recovery and myisam_recover_options to backup the data files'
	describe mysql_conf do
		its('mysqld.aria_recover') { should eq 'BACKUP'} # Keeps a backup of the data files.
		its('mysqld.aria_recover') { should eq 'FORCE' } # Runs the recovery even if it determines that more than one row from the data 		file will be lost. 			
		its('mysqld.aria_recover') { should eq 'QUICK' } # Does not check rows in the table if there are no delete blocks
		its('mysqld.myisam_recover_options') { should eq 'BACKUP' }
		its('mysqld.myisam_sort_buffer_size') { should eq '134217720'} # Size in bytes of the buffer allocated when creating or sorting 		indexes on a MyISAM table.			
	end
	end
	control 'speed-limit' do
	desc 'sets the speed limit to slaves'
	describe mysql_conf do
		its('mysqld.read_binlog_speed_limit') { should eq '0'}# Used to restrict the speed at which a replication slave can read the 			binlog from the master. This can be used to reduce the load on a master if many slaves need to download large amounts of old 			binlog files at the same time. 
	end
	end
	control 'Connection-priority' do
	desc 'checking thread-pool priority is auto'
	describe mysql_conf do
		its('mysqld.thread_pool_priority') { should eq 'high'} # High-priority connections usually start executing earlier than 		low-priority
	end
	end
	control'SQL-mode'  do
	desc 'cheking sql mode '
	describe mysql_conf do
		its('mysqld.sql_mode') { should eq 'STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'} 		#SQL_MODE is used for getting MariaDB to emulate behavior from other SQL servers
	end
	end
	control 'MariaDB-Conf' do
	title 'max-connection'
	desc 'No of maximum connection'
	describe mysql_conf do
		its('mysqld.max_connection') {should eq 100} # No of simultaneous client connection 100-300 for 2GB Ram and 1000 for 16GB Ram 			and it depends on workload
		its('mysqld.thread_stack') { should eq '200KB'} # Each thread takes some amount of Ram
	end
	end
	control 'mysql_session' do
	desc 'testing for matching databases'
	sql = mysql_session('root','password')
	describe sql.query(" show databases like \'test\';") do
  		its('stdout') { should_not match(/test/) }
	end
	end
end	

