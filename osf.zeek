
# This Zeek script caclulates OS-fingerprints based on SYN-Size, Win-Size and TTL
#
# Author: Maarten P. Dekker (m.dekker@student.fontys.nl)


module OSFingerprint;

export {
redef enum Log::ID += { LOG };
}

type OSFingerprintStorage: record {
        #packet values
        size:       string &default="";
        hdrs:       string &default="";
        oddities:   string &default="";
        #IP values
        ip4_hl:     count &default=0;
        ip_id:      count &default=0;
        ip_len:     count &default=0;
        df:         string &default="";
        ttl:        string &default="";
        #TCP values
        win_size:   string &default="";
        tcp_hl:     count &default=0;
        tcpopts:    string &default="";
        tcp_ack:    count &default=0;
        tcp_tser:   count &default=0;
        tcp_flags:  count &default=0;
        #SRC IP and connection UID
        src:        string &default="" &log;
        uid:        string &default="" &log;
        #Fingerprint Signatures
        satori_sig: string &default="" &log;
        csirt_sig:  string &default="" &log;
        #Values used for making sure that the script runs correctly        
        tcpoptready: bool &default=F;
        synready:    bool &default=F;
        pktready:    bool &default=F;
        readycount:  count &default=0;
};

redef record connection += {
       osfp: OSFingerprintStorage &optional;
};

const sep = ":";

event zeek_init() {
    Log::create_stream(OSFingerprint::LOG,[$columns=OSFingerprintStorage, $path="osfp"]);
}

function writeLog(c: connection){
    
        print(cat(c$osfp$tcpoptready) + " - " + cat(c$osfp$synready) + " - " + cat(c$osfp$pktready) + " - " + cat(c$uid));

        when((c$osfp$tcpoptready == T) && (c$osfp$synready == T) && (c$osfp$pktready == T)){

            #Build satori signature : Winsize -- TTL -- DF -- Headers Combined -- TCP Options -- oddities
            local signature = string_cat(c$osfp$win_size, sep, c$osfp$ttl, sep, c$osfp$df, sep, c$osfp$hdrs, sep, c$osfp$tcpopts, sep, c$osfp$oddities);
            c$osfp$satori_sig = signature;

            #write signature to the OSF LOG
            c$osfp$satori_sig = signature;
            Log::write(OSFingerprint::LOG, c$osfp);
        }

}

function computeNearTTL(info : count): string{
    local ttl : count;
    ttl = 9999;
    if((info > 0) && (info <= 16)){
        ttl = 16;
    }
    if((info > 16 && info <= 32)){
        ttl = 32;
    }
    if((info > 32 && info <= 60)){
        ttl = 60;
    }
    if((info > 60 && info <= 64)){
        ttl = 64;
    }
    if((info > 64 && info <= 128)){
        ttl = 128;
    }
    if(info > 128){
        ttl = 255;
    }
    if(ttl == 9999){
        ttl = info;
    }
    return cat(ttl);
}

function detectOddities(c: connection): string{

    local odd = "";
    local len = 9999;

    if(c$osfp$ip_id == 0){
        odd = odd + "Z";
    }
    if(c$osfp$ip4_hl > 20){
        odd = odd + "I";
    }
    
    len = (c$osfp$ip_len - c$osfp$ip4_hl - c$osfp$tcp_hl);

    if(len > 0){
        odd = odd + "D";
    }
    
    # value of 2 is a SYN packet
    if(c$osfp$tcp_flags == 2  && c$osfp$tcp_ack != 0){
        odd = odd + "A";
    }

    if(c$osfp$tcp_flags == 2 && c$osfp$tcp_tser != 0){
        odd = odd + "T";
    }

    if(odd == ""){
        odd = ".";
    }

    return odd;
}

# this function decodes the list of TCP options and assigns values of certain options
function decodeTCPOptions(c: connection, opt_vec : TCP::OptionList): string{
    local final_result = "";
    local res = "";
    local mss = 0;
    local tcpTSER = 0;

    for(i in opt_vec){

        if(opt_vec[i]$kind == 0){
            res = res + "E,";
        }
        else if(opt_vec[i]$kind == 1){
            res = res + "N,";
        }
        else if(opt_vec[i]$kind == 2){
            #Max segment size
            mss = opt_vec[i]$mss;
            res = res + string_cat("M" + cat(mss) + ",");
        }
        else if(opt_vec[i]$kind == 3){
            #Window Scale code
            local ws = opt_vec[i]$window_scale;
            res = res + string_cat("W" + cat(ws) + ",");
        }
        else if(opt_vec[i]$kind == 4){
            res = res + "S,";
        }
        else if(opt_vec[i]$kind == 5){
            res = res + "K,";
        }
        else if(opt_vec[i]$kind == 6){
            res = res + "J,";
        }
        else if(opt_vec[i]$kind == 7){
            res = res + "F,";
        }
        else if(opt_vec[i]$kind == 8){
            # TcpTimeStampEchoReply
            res = res + "T,";
            #local tcpTS = opt_vec[i]$send_timestamp;
            tcpTSER = opt_vec[i]$echo_timestamp;
        }
        else if(opt_vec[i]$kind == 9){
            res = res + "P,";
        }
        else if(opt_vec[i]$kind == 10){
            res = res + "R,";
        }
        else{
            res = res + "U,";
        }
    }
    #remove the "," from the end of the result
    final_result = cut_tail(res, 1);
    c$osfp$tcp_tser = tcpTSER;
    return final_result;
}

event new_packet(c: connection, p: pkt_hdr)
{

    if ( !c?$osfp ){
        c$osfp=OSFingerprintStorage();
    }

    if(c$osfp$pktready == T){
		return;
	}

    c$osfp$uid = cat(c$uid);

    if( p?$ip){
        #source ip adress
        c$osfp$src = cat(p$ip$src);
        #ip header length
        c$osfp$ip4_hl = p$ip$hl;
        #ip id
        c$osfp$ip_id = p$ip$id;
        #ip packet length
        c$osfp$ip_len = p$ip$len;
    }

    if( p?$tcp){
        #tcp header length
        c$osfp$tcp_hl = p$tcp$hl;
        #tcp flags
        c$osfp$tcp_flags = p$tcp$flags;
        #tcp ack value
        c$osfp$tcp_ack = p$tcp$ack;
    }

    if(c$osfp$tcp_flags == 2){
        
        c$osfp$oddities = detectOddities(c);
        
        c$osfp$pktready = T;
        c$osfp$readycount = c$osfp$readycount + 1;

        if(c$osfp$readycount == 3){
            writeLog(c);
        }
    }
}

event tcp_options(c: connection, is_orig: bool, options: TCP::OptionList)
{

	if(c$osfp$tcpoptready == T){
		return;
	}

    if ( !c?$osfp )
        c$osfp=OSFingerprintStorage();
        
    local opt_vec: TCP::OptionList = options;

    local decoded_tcp_options = "";

    decoded_tcp_options = decodeTCPOptions(c, opt_vec);
    c$osfp$tcpopts = decoded_tcp_options;

    c$osfp$tcpoptready = T;
    c$osfp$readycount = c$osfp$readycount + 1;

    if(c$osfp$readycount == 3){
        writeLog(c);
    }
}

event connection_SYN_packet(c: connection, pkt: SYN_packet)
{

	if(c$osfp$synready == T){
		return;
	}

    if ( !c?$osfp ){
        c$osfp=OSFingerprintStorage();
    }

    #syn packet size
    c$osfp$size = cat(pkt$size);

    #tcp window size
    c$osfp$win_size = cat(pkt$win_size);

    #compute near TTL
    c$osfp$ttl = computeNearTTL(pkt$ttl);

    #compute signature for CSIRT-MU Passive Pingerprint DB
    #syntax is SYN_SIZE -- WIN_SIZE -- TTL
    local csirt_sep = ";";
    local csirt_ttl = 0;
    if(pkt$ttl > 64){
      csirt_ttl = 128;
    }
    else{
      csirt_ttl = 64;
    }
    local csirt_sig = string_cat(csirt_sep, c$osfp$size, csirt_sep, c$osfp$win_size, csirt_sep, cat(csirt_ttl), csirt_sep);
    #local csirt_srcip = cat(c$id$orig_h);
    #c$osfp$csirt_srcip = csirt_srcip;
    c$osfp$csirt_sig = csirt_sig;

    #dont fragment bit
    if(pkt$DF == T){
        c$osfp$df = cat(1);
    }
    if(pkt$DF == F){
        c$osfp$df = cat(0);
    }

    #combine headerlength of ip and tcp
    local headerscombined = (c$osfp$ip4_hl + c$osfp$tcp_hl);
    c$osfp$hdrs = cat(headerscombined);
    
    #print("almostready SYN" + cat(c$uid));

    c$osfp$synready = T;
    c$osfp$readycount = c$osfp$readycount + 1;

    if(c$osfp$readycount == 3){
        writeLog(c);
    }
}