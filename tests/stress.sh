#!/bin/bash
set -e

# Requires:
# - bash (and not other POSIX shells)
# - lsof
# - dtach
# - irssi

# Config:
CHANNEL="#testchan"
RUNNERS=300
MCOUNT=2000
MDELAY=0.02


# create a working directory
wd=$(mktemp -d --tmpdir ircstream.XXXX)

# initialize, i.e. create the channel
printf "$CHANNEL\tmessage init\n" > /dev/udp/localhost/9390

for instance in $(seq -w 1 $RUNNERS); do
	printf "\rStarting runner $instance/$RUNNERS"
	irssi_home=$wd/$instance
	mkdir $irssi_home
	cat <<-EOF > $irssi_home/config
	settings = {
	  core = {
	    real_name = "testreal";
	    user_name = "testuser";
	    nick = "testnick-$instance";
	  };
	  "fe-common/core" = {
	    autolog = "yes";
	    autolog_path = "$irssi_home/logs/\$0.log";
	    term_charset = "utf-8";
	  };
	};
	
	servers = (
	  {
	    address = "localhost";
	    chatnet = "ircstream";
	    port = "6667";
	    use_tls = "no";
	    tls_verify = "no";
	    autoconnect = "yes";
	  }
	);
	
	chatnets = {
	  ircstream = {
	    type = "IRC";
	  };
	};
	
	channels = (
	  {
	    name = "$CHANNEL";
	    chatnet = "ircstream";
	    autojoin = "yes";
	  }
	);
	EOF

	dtach -n $wd/$instance.sock irssi --home=$irssi_home
done
echo

pids=$(lsof -t -a -c dtach +D $wd | xargs || true)

sleep 0.5

SECONDS=0
for i in $(seq 1 $MCOUNT); do
	printf "\rSending message $i/$MCOUNT [${SECONDS}s]"
	printf "$CHANNEL\tmessage ${i}\n" > /dev/udp/localhost/9390
	sleep $MDELAY
done
echo

# give workers some time to 
sleep 0.5

echo "Killing runners..."
if [ "$pids" != "" ]; then
	kill $pids
fi

echo "Validating results..."
for instance in $(seq -w 1 $RUNNERS); do
	count=$(grep -c rc-pmtpa $wd/$instance/logs/\#testchan.log || true)
	if [ "$count" != "$MCOUNT" ]; then
		echo " Instance $instance failed, $count != $MCOUNT"
	fi
done
echo "All done!"
echo
echo "You can inspect or remove $wd now"
