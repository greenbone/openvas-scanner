# OpenVAS Documentation (WORK IN PROGRESS)

**Introduction**:
The OpenVAS project aims to provide a comprehensive vulnerability scanning and management solution. This documentation serves as a guide to understanding and utilizing the OpenVAS project effectively.

**Document Structure**:
The documentation of this project contains three parts:
1. Doxygen:
It is used as a documentation of the internal c library. To build the doxygen documentation call `make doxygen-full`. This will generate the necessary documentation.

2. Man:
In the man folder you can find manual pages of the executables of the project. These are automatically installed when calling `make install`. Additionally, you can generate man pages of the built-in NASL functions. These can be generated with `make nasl-man`.  Note that the NASL function man pages are not automatically installed, and you need to have pandoc installed to generate them.

3. Manual:
It is also possible to generate a general purpose manual of the openvas project. The manual can be generated with `make manual` and provides comprehensive information about the OpenVAS project including the NASL-documentation. Generating the manual also requires pandoc.

**Readability and Formatting**:
- Utilize headings, subheadings, and bullet points to enhance readability.
- Ensure consistent formatting throughout the document.

**Contributing**:
We welcome contributions to the OpenVAS project and its documentation. If you would like to contribute, please follow the guidelines below:
- Bug Reports: Submit bug reports using the specified channels or issue tracker.
- Improvements: Suggest improvements by submitting pull requests or proposing changes.
- Code Contributions: If you wish to contribute code, please review the contribution guidelines in the project repository.

**Licensing**:
The OpenVAS project is distributed under [specify the license here]. When contributing to the project or modifying the documentation, please adhere to the license requirements.

**Build and Installation**:
To build and install OpenVAS:
1. [Provide step-by-step instructions for building and installing OpenVAS]
2. [Include information about dependencies and prerequisites]

**External Tool Dependencies**:
If the documentation references external tools like Doxygen or pandoc, please ensure you have the following installed:
- Doxygen [version]: [Provide installation instructions or link to relevant resources]
- Pandoc [version]: [Provide installation instructions or link to relevant resources]

**Additional Resources**:
- [Link to community forums, mailing lists, or repositories]

**Feedback and Contributions**:
We value your feedback! If you have any suggestions or encounter issues with the documentation, please don't hesitate to reach out. We also encourage contributions to improve the documentation. Feel free to suggest changes, report issues, or submit pull requests to make the documentation even better.

Thank you for using OpenVAS!


