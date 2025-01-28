# Cryptography_public

This project was developed for the subject "Teoría de Códigos y Criptografía" at Universidad de Almería. It focuses on various cryptographic methods and implementations, including a ransomware concept that runs on a Linux environment for educational purposes.

## Repository Information
- Educational Purpose: This project demonstrates the concepts of cryptographic techniques and their applications in creating ransomware. It is intended solely for educational purposes to understand the workings of such systems and to promote awareness of cybersecurity.

- Language Composition of This Repo:
    - C++: 75.8%
    - HTML: 12.4%
    - Python: 8.3%
    - CMake: 3.5%

## Features

1. **Ransomware Implementation**
    - Demonstrates how encryption can be misused to hold data ransom.
    - Includes encryption and decryption routines that simulate ransomware behavior in a controlled environment.

2. **Cryptographic Algorithms**
    - Contains examples of symmetric and asymmetric encryption.
    - Showcases algorithms like AES, McEliece, and other classical/modern cipher techniques.

3. **Error-Correcting Codes**
    - Demonstrates how coded data can detect and correct errors.
    - Highlights usage for reliable data transmission and storage.

4. **Build Configurations (CMake)**
    - Facilitates easy configuration for C++ projects.
    - Ensures consistent compilation across multiple platforms.

5. **Post-Quantum Cryptography**
    - Implements post-quantum cryptographic algorithms, such as McEliece.
    - Demonstrates the generation and handling of asymmetric keys using quantum-resistant methods.

6. **Python Project (Website Folder)**
    - A Flask-based website demonstrating how certificates work in browsers.
    - Provides an example of setting up HTTPS and managing certificates.

## Getting Started

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/Toad882/Cryptography_public.git
   cd Cryptography_public
   ```

2. **Build Instructions (for C++ projects)**
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```
   After successful compilation, you can run your compiled programs from the build folder. The build process will generate the following files:
   - private_key.pem
   - PearOS executable (ransomware)
   - decrypt executable (decrypts the files encrypted by the ransomware)

3. **HTML Demos**  
   Open the relevant HTML file in your web browser to see interactive demonstrations or additional project information.

4. **Running the Flask Website**
   ```bash
   cd Website
   python app.py
   ```
   Make sure you have Flask installed and any required dependencies. Once running, visit the hosted URL in your browser to explore how certificates are handled.
## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
