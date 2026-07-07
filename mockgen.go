//go:build gomock || generate

package quic

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_send_conn_test.go github.com/xssnick/quic-go-ton SendConn"
type SendConn = sendConn

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_raw_conn_test.go github.com/xssnick/quic-go-ton RawConn"
type RawConn = rawConn

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_sender_test.go github.com/xssnick/quic-go-ton Sender"
type Sender = sender

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_stream_sender_test.go github.com/xssnick/quic-go-ton StreamSender"
type StreamSender = streamSender

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_stream_control_frame_getter_test.go github.com/xssnick/quic-go-ton StreamControlFrameGetter"
type StreamControlFrameGetter = streamControlFrameGetter

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_stream_frame_getter_test.go github.com/xssnick/quic-go-ton StreamFrameGetter"
type StreamFrameGetter = streamFrameGetter

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_frame_source_test.go github.com/xssnick/quic-go-ton FrameSource"
type FrameSource = frameSource

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_ack_frame_source_test.go github.com/xssnick/quic-go-ton AckFrameSource"
type AckFrameSource = ackFrameSource

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_sealing_manager_test.go github.com/xssnick/quic-go-ton SealingManager"
type SealingManager = sealingManager

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_unpacker_test.go github.com/xssnick/quic-go-ton Unpacker"
type Unpacker = unpacker

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_packer_test.go github.com/xssnick/quic-go-ton Packer"
type Packer = packer

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_mtu_discoverer_test.go github.com/xssnick/quic-go-ton MTUDiscoverer"
type MTUDiscoverer = mtuDiscoverer

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_conn_runner_test.go github.com/xssnick/quic-go-ton ConnRunner"
type ConnRunner = connRunner

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/xssnick/quic-go-ton -destination mock_packet_handler_test.go github.com/xssnick/quic-go-ton PacketHandler"
type PacketHandler = packetHandler

//go:generate sh -c "go tool mockgen -typed -package quic -self_package github.com/xssnick/quic-go-ton -self_package github.com/xssnick/quic-go-ton -destination mock_packetconn_test.go net PacketConn"
