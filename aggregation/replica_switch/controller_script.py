multicast_grp = bfrt.pre.node.add(1)

entry = bfrt.pre.node.entry(MULTICAST_NODE_ID = 1,MULTICAST_RID = 1,DEV_PORT = [1, 0]).push()

entry = bfrt.pre.mgid.entry(MGID = 1, MULTICAST_NODE_ID = [1,], MULTICAST_NODE_L1_XID_VALID = [False,],MULTICAST_NODE_L1_XID = [0, ]).push()

