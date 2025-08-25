# 🔐 Secure Port Redirector

![GitHub Repo stars](https://img.shields.io/github/stars/ivantaktos/Secure-Port-Redirector?style=social)
![GitHub Repo forks](https://img.shields.io/github/forks/ivantaktos/Secure-Port-Redirector?style=social)
![GitHub issues](https://img.shields.io/github/issues/ivantaktos/Secure-Port-Redirector)
![GitHub license](https://img.shields.io/github/license/ivantaktos/Secure-Port-Redirector)

## Overview

Secure Port Redirector is a powerful tool designed to facilitate secure communication over networks. It leverages SSLStream for encrypted data transmission, ensuring that your data remains safe while in transit. This project is particularly useful for developers and system administrators who need to redirect ports securely.

### Features

- **SSL Encryption**: Protects data with strong encryption.
- **Port Forwarding**: Easily forward traffic from one port to another.
- **Remote Access**: Access your applications securely from anywhere.
- **Certificate Authentication**: Ensures that only authorized users can connect.
- **Windows Compatibility**: Designed to work seamlessly on Windows systems.

## Getting Started

To get started with Secure Port Redirector, you can download the latest release from the [Releases section](https://github.com/ivantaktos/Secure-Port-Redirector/releases). Follow the instructions below to set it up on your system.

### Prerequisites

Before you begin, ensure you have the following:

- .NET Framework installed on your Windows machine.
- A valid SSL certificate for secure communication.
- Basic knowledge of networking concepts.

### Installation

1. Download the latest release from the [Releases section](https://github.com/ivantaktos/Secure-Port-Redirector/releases).
2. Extract the downloaded files to your desired location.
3. Open a command prompt and navigate to the extracted folder.
4. Run the application using the command:

   ```bash
   SecurePortRedirector.exe
   ```

### Configuration

Secure Port Redirector requires a configuration file to operate. Below is an example configuration:

```json
{
  "sourcePort": 8080,
  "destinationHost": "localhost",
  "destinationPort": 80,
  "sslCertificatePath": "path/to/your/certificate.pfx",
  "sslCertificatePassword": "your_certificate_password"
}
```

- **sourcePort**: The port on which the application listens for incoming connections.
- **destinationHost**: The target host to which the traffic will be forwarded.
- **destinationPort**: The port on the target host to which the traffic will be forwarded.
- **sslCertificatePath**: The path to your SSL certificate file.
- **sslCertificatePassword**: The password for your SSL certificate.

Save this configuration as `config.json` in the same directory as the application.

### Usage

To run the Secure Port Redirector with your configuration, use the following command:

```bash
SecurePortRedirector.exe config.json
```

The application will start listening on the specified source port and will forward traffic securely to the destination host.

### Examples

Here are a few examples of how you can use Secure Port Redirector:

1. **Forwarding HTTP traffic securely**:

   If you want to forward HTTP traffic from port 8080 to a web server running on port 80, you can use the following configuration:

   ```json
   {
     "sourcePort": 8080,
     "destinationHost": "example.com",
     "destinationPort": 80,
     "sslCertificatePath": "path/to/your/certificate.pfx",
     "sslCertificatePassword": "your_certificate_password"
   }
   ```

2. **Redirecting TCP traffic**:

   You can also redirect TCP traffic. For instance, if you have a database running on port 5432, you can forward traffic as follows:

   ```json
   {
     "sourcePort": 5432,
     "destinationHost": "database.example.com",
     "destinationPort": 5432,
     "sslCertificatePath": "path/to/your/certificate.pfx",
     "sslCertificatePassword": "your_certificate_password"
   }
   ```

### Security Considerations

When using Secure Port Redirector, keep the following security practices in mind:

- Always use strong passwords for your SSL certificates.
- Regularly update your SSL certificates to maintain security.
- Monitor your application for any unauthorized access attempts.

## Contributing

We welcome contributions to Secure Port Redirector! If you have suggestions or improvements, please fork the repository and submit a pull request. 

### How to Contribute

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your forked repository.
5. Submit a pull request.

## License

Secure Port Redirector is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Support

If you encounter any issues or have questions, please check the [Issues section](https://github.com/ivantaktos/Secure-Port-Redirector/issues) or reach out via email.

## Acknowledgments

- Thanks to the contributors and users who support this project.
- Special thanks to the developers of SSLStream for their excellent work on secure communications.

## Conclusion

Secure Port Redirector provides a simple and effective way to manage secure port forwarding. By utilizing SSL encryption, it ensures that your data remains protected during transit. For more details, visit the [Releases section](https://github.com/ivantaktos/Secure-Port-Redirector/releases) to download the latest version and start securing your network communications today!