import socket
import struct
import logging
from pathlib import Path

logger = logging.getLogger("deepfence.blocker.xdp")

try:
    from bcc import BPF
except ImportError:
    BPF = None
    logger.warning("BCC (bpfcc) 모듈을 찾을 수 없습니다. XDP 차단 기능이 비활성화됩니다.")

class XDPManager:
    """eBPF/XDP를 이용한 초고속 하드웨어 레벨 IP 차단 매니저"""
    
    def __init__(self, interface: str = "ens3"):
        self.interface = interface
        self.bpf = None
        self.blocklist = None
        
        if BPF is None:
            return
            
        try:
            current_dir = Path(__file__).parent
            c_file = current_dir / "xdp_blocker.c"
            
            if not c_file.exists():
                logger.error(f"XDP 소스 코드를 찾을 수 없습니다: {c_file}")
                return
                
            # C 코드 컴파일 및 커널 적재
            self.bpf = BPF(src_file=str(c_file))
            self.fn = self.bpf.load_func("xdp_drop_ips", BPF.XDP)
            
            # 네트워크 인터페이스에 XDP 프로그램 부착
            self.bpf.attach_xdp(self.interface, self.fn, 0)
            
            # C 코드의 BPF_HASH 맵 가져오기
            self.blocklist = self.bpf.get_table("blocklist")
            logger.info(f"XDP 차단 모듈이 {self.interface} 인터페이스에 성공적으로 부착되었습니다.")
        except Exception as e:
            logger.error(f"XDP 모듈 초기화 실패 (root 권한 필요): {e}")
            self.bpf = None

    def block_ip(self, ip_address: str) -> bool:
        """1밀리초 만에 즉각 차단 (리로드 불필요)"""
        if not self.bpf or not self.blocklist:
            return False
            
        try:
            # 아키텍처나 NIC 드라이버(OpenStack KVM 등)에 따른 엔디안 차이를 무시하기 위해
            # 정방향(Big Endian)과 역방향(Little Endian) 포맷을 모두 차단 리스트에 꽂아넣습니다. (Bulletproof)
            raw_bytes = socket.inet_aton(ip_address)
            ip_le = struct.unpack("<I", raw_bytes)[0]
            ip_be = struct.unpack(">I", raw_bytes)[0]
            
            self.blocklist[self.blocklist.Key(ip_le)] = self.blocklist.Leaf(1)
            self.blocklist[self.blocklist.Key(ip_be)] = self.blocklist.Leaf(1)
            
            logger.info(f"[XDP] {ip_address} 하드웨어 레벨 차단 완료! (LE:{ip_le}, BE:{ip_be})")
            return True
        except Exception as e:
            logger.error(f"XDP 차단 실패 ({ip_address}): {e}")
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """차단 해제"""
        if not self.bpf or not self.blocklist:
            return False
            
        try:
            raw_bytes = socket.inet_aton(ip_address)
            ip_le = struct.unpack("<I", raw_bytes)[0]
            ip_be = struct.unpack(">I", raw_bytes)[0]
            
            for packed_ip in (ip_le, ip_be):
                try:
                    del self.blocklist[self.blocklist.Key(packed_ip)]
                except KeyError:
                    pass
            logger.info(f"[XDP] {ip_address} 하드웨어 차단 해제 완료!")
            return True
        except Exception as e:
            logger.error(f"XDP 차단 해제 실패 ({ip_address}): {e}")
            return False
            
    def cleanup(self):
        """프로세스 종료 시 XDP 모듈 안전하게 분리"""
        if self.bpf:
            try:
                self.bpf.remove_xdp(self.interface, 0)
                logger.info(f"XDP 차단 모듈이 {self.interface} 인터페이스에서 해제되었습니다.")
            except Exception as e:
                logger.error(f"XDP 모듈 해제 중 오류 발생: {e}")
