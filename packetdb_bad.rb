#!/usr/bin/env ruby -wKU

require 'rubygems'
require 'sqlite3'
require 'pcap'

DBFILENAME = "/home/shigematsu/db/packetdb.sqlite3"

DBDIR = File.dirname( DBFILENAME )
DBNAME = File.basename( DBFILENAME )

Dir.chdir( DBDIR )
db = SQLite3::Database.new( DBFILENAME )

sql = <<SQL
# DROP TABLE tcppackets;
SQL
puts "drop table tcppackets..."

# db.execute_batch(sql)

sql = <<SQL
# DROP TABLE udppackets;
SQL
puts "drop table udppackets..."

# db.execute_batch(sql)

sql = <<SQL
CREATE TABLE tcppackets_bad (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    time          REAL NOT NULL,
    size          INTEGER NOT NULL,
    tcp_data_len  INTEGER NOT NULL, 
    ip_src        INTEGER NOT NULL,
    tcp_sport     INTEGER NOT NULL,
    ip_dst        INTEGER NOT NULL,
    tcp_dport     INTEGER NOT NULL,
    tcp_flags_s   TEXT NOT NULL,
    tcp_seq       INTEGER NOT NULL,
    tcp_data      TEXT );
CREATE TABLE udppackets_bad (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    time          REAL NOT NULL,
    size          INTEGER NOT NULL,
    udp_len  INTEGER NOT NULL, 
    ip_src        INTEGER NOT NULL,
    udp_sport     INTEGER NOT NULL,
    ip_dst        INTEGER NOT NULL,
    udp_dport     INTEGER NOT NULL,
    udp_data      TEXT );  
SQL
puts "define table tcppackets..."
db.execute_batch(sql)

puts "insert values..."

db.transaction do


File::open("/home/shigematsu/list/filelist_bad") {|file|
  while malpcap = file.gets
    filename = malpcap.chomp
    puts filename

cap = Pcap::Capture.open_offline(filename)
cap.setfilter("ip")
cap.loop do |pkt|
  if pkt.ip? and pkt.tcp?
    db.execute( " insert into tcppackets_bad values ( null, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )", pkt.time.to_f, pkt.size, pkt.tcp_data_len, pkt.ip_src, pkt.tcp_sport, pkt.ip_dst, pkt.tcp_dport, pkt.tcp_flags_s, pkt.tcp_seq, pkt.tcp_data )
  end
  if pkt.ip? and pkt.udp?
    db.execute( " insert into udppackets_bad values ( null, ?, ?, ?, ?, ?, ?, ?, ? )", pkt.time.to_f, pkt.size, pkt.udp_len, pkt.ip_src, pkt.udp_sport, pkt.ip_dst, pkt.udp_dport, pkt.udp_data )
  end
end
cap.close
end
}
end
