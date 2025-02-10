ip_addr=$1
a=6000
#noport="$(nmap -sV -T4 $ip_addr -p 1-$a | grep -A 0 shown | grep -o '[0-9]*[0-9]*[0-9]*[0-9]*')"
#if [ "$noport" != '' ]; then
  value="$(python3 genuinefinal22.py $ip_addr)"
  #value="$(nmap -sV -T4 $ip_addr -p 1-$a| grep -A $(($a-$noport)) PORT )"
  #value="$(nmap 172.17.15.242 -p 1-6000| grep -A $(($a-$noport)) PORT | grep -o '[0-9]*[0-9]*[0-9]*[0-9]*' )"
  #value="$(nmap 172.17.15.242 | grep -A $(($a-998)) PORT)"
  #echo $noport | tr 'open ' '\n'
  echo "$value"
  echo "$value" >"output$ip_addr.txt"
  i=0
  k=0
  #for word in $value
  #do
  #	i=$((i+1))
  #	if [ $i -ge $k ]
  #	then
  #		a[$i]=$word
  #	fi
  #done
  #for (( j=1; j<=$i; j++ ))
  #do
  #	echo "${a[$j]}|${a[$((j+1))]}|${a[$((j+2))]}|${a[$((j+3))]}"
  #	if [ "${a[$((j+2))]}" == "ssh" ]
  #	then
  #		k=2
  #	fi
  #	j=$((j+3))
  #	echo "$a[$entry]"
  #done
  present="$(echo $value | grep 'ssh' | grep 'open')"
  if [ "$present" != '' ]; then
    echo "#****************SSH Downgrade*****************"
    sudo bash sshdowngrade.sh $ip_addr
    echo "#******************SSH ATTEMPT*****************"
    sudo bash sshattempt.sh $ip_addr
  fi
  present="$(echo $value | grep 'ssl\|https\|ftps' | grep 'open')"
  if [ "$present" != '' ]; then
    echo "#****************SSL Version*****************"
    sudo bash sslversion.sh $ip_addr
  fi
else
  echo "No port open or Firewall blocks"
fi
