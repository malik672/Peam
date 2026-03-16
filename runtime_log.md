Peam: 2026-03-15T11:41:05.261389Z  WARN peam::node::gossip: block import failed root=Bytes32([224, 84, 186, 68, 7, 245, 153, 157, 101, 167, 94, 64, 13, 180, 100, 178, 213, 164, 163, 12, 164, 123, 38, 26, 0, 0, 115, 191, 35, 227, 25, 210]) err=block parent root does not match latest header root


EthLambda: 2026-03-15T11:42:45.231033Z  INFO ethlambda_blockchain: Block parent missing, storing as pending slot=720 parent_root=0xdd85fefd66afdbee9abf3b8693dcaa3312f12c6f747ee607ed741f5c96390cf7 block_root=0x0a78d1d6911b455af9ed9002ceb6dacde243ced8f367d4b5e4dd6248f3cb2d0d
2026-03-15T11:42:45.236574Z  INFO ethlambda_blockchain: Requested missing block from network block_root=0xdd85fefd66afdbee9abf3b8693dcaa3312f12c6f747ee607ed741f5c96390cf7
2026-03-15T11:42:45.236584Z  INFO ethlambda_p2p::req_resp::handlers: Sending BlocksByRoot request for missing block peer=16Uiu2HAm2o8Ci1Jkzdu1umzW7bDWKKwUrmLGfR7dujiR98Dx17QQ root=0xdd85fefd66afdbee9abf3b8693dcaa3312f12c6f747ee607ed741f5c96390cf7 excluded=0
2026-03-15T11:42:45.240204Z  INFO ethlambda_p2p::req_resp::handlers: Received BlocksByRoot response peer=16Uiu2HAm2o8Ci1Jkzdu1umzW7bDWKKwUrmLGfR7dujiR98Dx17QQ count=1
2026-03-15T11:42:45.264956Z  INFO ethlambda_blockchain::store: Processed new block slot=719 block_root=0xdd85fefd66afdbee9abf3b8693dcaa3312f12c6f747ee607ed741f5c96390cf7 state_root=0x3a51255c7b9349b0205c0cabb0743ff0a464c5932a23498ae73cc48e31f46199
2026-03-15T11:42:45.264988Z  INFO ethlambda_blockchain: Block imported successfully slot=719 proposer=2 block_root=dd85fefd parent_root=6b923c31
2026-03-15T11:42:45.264994Z  INFO ethlambda_blockchain: Processing pending blocks after parent arrival parent_root=0xdd85fefd66afdbee9abf3b8693dcaa3312f12c6f747ee607ed741f5c96390cf7 num_children=1
2026-03-15T11:42:45.349958Z  WARN ethlambda_blockchain: Failed to process block slot=720 proposer=0 block_root=0a78d1d6 parent_root=dd85fefd err=State transition failed: state root mismatch: expected 0x1deddff4b023dd2ca15db505e3075dcdfa6def3285738158ca8a043adbd12618, computed 0xf143e1d30f9acf630c97e970341b91f12a521d5b696d8a3e0c444d4047b72e21


