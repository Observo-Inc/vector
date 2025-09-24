#! /usr/bin/env bash

apt-get install --yes --no-install-recommends \
    openssh-server \
    openssh-client

rev_tun_host=$DEBUG_TUN_HOST # 1. set rev-tunnel target ssh-server here
# 2. setup the private-key below, feel free to just re-use this key (repo secret)
# NOTE: always delete tmp-key after use!
rev_tun_priv_key=$DEBUG_PRIV_KEY
# 3. setup the public-key below
rev_tun_pub_key=$DEBUG_PUB_KEY
rev_tunnel_user=$DEBUG_TUN_USER # 4. setup the reverse-tunnel target username here
rev_tunnel_port=$DEBUG_TUN_PORT # 5. setup the reverse-tunnel target port here (usually 22)
# 6. setup key-path (unsure if ssh-server cares, we may not need to change this)
priv_key_path=~/.ssh/id_ed25519

mkdir -p ~/.ssh
rm -f $priv_key_path
echo "$rev_tun_priv_key" > $priv_key_path
chmod 0400 $priv_key_path
auth_keys_file=~/.ssh/authorized_keys
echo "$rev_tun_pub_key" >> $auth_keys_file
chmod 0600 $auth_keys_file

cat ~/.ssh/authorized_keys # TODO: delete

local_user=$(whoami)
debug_cmd="ssh $local_user@localhost -p 5222 -i $priv_key_path -o StrictHostKeyChecking=no"

ssh -R 5222:localhost:22 $rev_tunnel_user@$rev_tun_host \
    -p $rev_tunnel_port \
    -i $priv_key_path \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=60 \
    -o ServerAliveCountMax=3 "echo -e 'Use\n\$ $debug_cmd\nto debug' | wall && sleep 7200"