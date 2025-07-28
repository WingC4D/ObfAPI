### **Project Title:** ObfAPI | A C-Based Exploration of Static Evasion Techniques
---
#### Technolegies Used:
<p align="middle">
  <href = "https://skillicons.dev">
  <img src="https://skillicons.dev/icons?i=c,visualstudio,obsidian,windows" >
</p>

---
### **Project Overview:**
This repository contains a C module developed as a personal exploration of the engineering principles behind static analysis evasion. The primary goal of this project was to move beyond theory and gain practical, hands-on experience with the kind of problems presented in modern malware development.

This work is an exercise in refining concepts and solving problems, not inventing them from scratch. The inspiration and foundational logic for these techniques come from the excellent curriculum at **Maldev Academy** and the brilliant work of its instructors, **mr.d0x** and **NUL0x4C**. The initial idea was sparked by real-world threat intelligence, specifically the CapitalOne news piece on the **Hive Ransomware** family's use of IP-based obfuscation, which also inspired the HellShell tool.

---
### **Core Features & Engineering Decisions**

This module provides a framework for obfuscating a binary payload into multiple text-based formats and deobfuscating it using two distinct strategies.

- **Multi-Schema Obfuscation**: Implemented encoding schemas for IPv4, IPv6, and MAC addresses.
    
- **Custom Padding Algorithm**: To better understand data manipulation, I designed a custom, data-dependent padding algorithm. This was an exercise in creating a reversible process to obscure payload metadata, presenting a greater challenge to analysis than a simple `'\0'` / `NOP`-padding.
    
- **A Study in Deobfuscation Trade-offs**: For each schema, the module provides two deobfuscation implementations to explore the crucial trade-off between stealth and portability:
    
    - **"Living off the Land" (Windows):** A stealth-oriented approach using undocumented NTAPI functions (`Rtl...StringToAddress`) meant to minimize the tool's fingerprint on Windows systems.
        
    - **Portable C Implementation:** A self-contained, high-performance version built with no OS-specific dependencies, designed to be compatible across different platforms.
        
- **API Design**: The framework is built around a reusable API with a focus on type safety and clear `IN`/`OUT` parameters to facilitate easier integration and testing.
    
- **Performance Optimization**: As a practical exercise, a key conversion routine was re-engineered to replace slower floating-point math with more efficient integer arithmetic.
    
---
### **Personal Learning Goals**
- This project was a significant part of my journey in learning C since January. It pushed me to master difficult concepts like multi-level pointer manipulation, robust memory management, and clean API design. It serves as a tangible result of the incredible instruction provided by Boot.Dev & Maldev Academy,  respectively, and the inspiration drawn from the real-world work of security researchers.

---
#### **Future Improvements & Known Limitations**

- ⚠️As this is an active learning project, there are several areas for planned improvement. A current limitation of the custom padding algorithm is its handling of very small input chunks, which can result in predictable padding bytes.⚠️

> The next planned iteration will address this by re-engineering the padding logic to use a more robust, non-linear transformation inspired by block cipher principles. This will ensure high-entropy padding is generated in all scenarios, further increasing the complexity for static analysis.

---
## Demo:

### Mac:
<img width="1365" height="463" alt="Screenshot 2025-07-28 205714" src="https://github.com/user-attachments/assets/35e873dd-bc41-4f14-a952-e1bcd2a786f6" />

---

### IPv4: 

<img width="1371" height="473" alt="Screenshot 2025-07-28 205912" src="https://github.com/user-attachments/assets/10c338b6-b48f-414c-9c1b-80d8eddf2e72" />


### IPv6:
<img width="1362" height="508" alt="image" src="https://github.com/user-attachments/assets/8fb46573-052f-479c-a939-6b73596af846" />
