#this is for asynchronous replication
multicast_grp = bfrt.pre.node.add(1)

entry = bfrt.pre.node.entry(MULTICAST_NODE_ID = 1,MULTICAST_RID = 1,DEV_PORT = [132,188, 189]).push()

entry = bfrt.pre.mgid.entry(MGID = 1, MULTICAST_NODE_ID = [1,], MULTICAST_NODE_L1_XID_VALID = [False,],MULTICAST_NODE_L1_XID = [0, ]).push()



#this is just for training without replication
multicast_grp = bfrt.pre.node.add(1)

entry = bfrt.pre.node.entry(MULTICAST_NODE_ID = 1,MULTICAST_RID = 1,DEV_PORT = [188, 132]).push()

entry = bfrt.pre.mgid.entry(MGID = 1, MULTICAST_NODE_ID = [1,], MULTICAST_NODE_L1_XID_VALID = [False,],MULTICAST_NODE_L1_XID = [0, ]).push()


#just talk to each other
table1 = bfrt.serene.pipe.SwitchIngress.ipv4_lpm
entry = table1.entry_with_ipv4_forward(dst_addr=0x0a320106 , dst_mac=0xb8599fdf07cb, port="188").push()

entry = table1.entry_with_ipv4_forward(dst_addr=0x0a320101 , dst_mac=0x00154d1211a9, port="132").push()

