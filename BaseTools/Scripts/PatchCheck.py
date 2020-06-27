#  Copyright (c) 2020, ARM Ltd. All rights reserved.<BR>
import email.header

                not lines[i].startswith('git-svn-id:') and
                not lines[i].startswith('Reviewed-by') and
                not lines[i].startswith('Acked-by:') and
                not lines[i].startswith('Tested-by:') and
                not lines[i].startswith('Reported-by:') and
                not lines[i].startswith('Suggested-by:') and
                not lines[i].startswith('Signed-off-by:') and
                not lines[i].startswith('Cc:')):
        self.LicenseCheck(self.lines, self.count)
    def LicenseCheck(self, lines, count):
        self.ok = True
        self.startcheck = False
        self.license = True
        line_index = 0
        for line in lines:
            if line.startswith('--- /dev/null'):
                nextline = lines[line_index + 1]
                added_file = self.Readdedfileformat.search(nextline).group(1)
                added_file_extension = os.path.splitext(added_file)[1]
                if added_file_extension in self.file_extension_list:
                    self.startcheck = True
                    self.license = False
            if self.startcheck and self.license_format_preflix in line:
                if self.bsd2_patent in line or self.bsd3_patent in line:
                    self.license = True
                else:
                    for optional_license in self.license_optional_list:
                        if optional_license in line:
                            self.license = True
                            self.warning(added_file)
            if line_index + 1 == count or lines[line_index + 1].startswith('diff --') and self.startcheck:
                if not self.license:
                    error_message = "Invalid License in: " + added_file
                    self.error(error_message)
                self.startcheck = False
                self.license = True
            line_index = line_index + 1

    def warning(self, *err):
        count = 0
        for line in err:
            warning_format = 'Warning: License accepted but not BSD plus patent license in'
            print(warning_format, line)
            count += 1

                if self.filename.endswith('.sh') or \
                    self.filename.startswith('BaseTools/BinWrappers/PosixLike/') or \
                    self.filename.startswith('BaseTools/Bin/CYGWIN_NT-5.1-i686/') or \
                    self.filename == 'BaseTools/BuildEnv':
                    # Some linux shell scripts don't end with the ".sh" extension,
                    # they are identified by their path.
                if self.filename == '.gitmodules' or \
                   self.filename == 'BaseTools/Conf/diff.order':
                    # .gitmodules and diff orderfiles are used internally by git
                    # use tabs and LF line endings.  Do not enforce no tabs and
                    # do not enforce CR/LF line endings.
        if self.force_crlf and eol != '\r\n' and (line.find('Subproject commit') == -1):
    license_format_preflix = 'SPDX-License-Identifier'

    bsd2_patent = 'BSD-2-Clause-Patent'

    bsd3_patent = 'BSD-3-Clause-Patent'

    license_optional_list = ['BSD-2-Clause', 'BSD-3-Clause', 'MIT', 'Python-2.0', 'Zlib']

    Readdedfileformat = re.compile(r'\+\+\+ b\/(.*)\n')

    file_extension_list = [".c", ".h", ".inf", ".dsc", ".dec", ".py", ".bat", ".sh", ".uni", ".yaml", ".fdf", ".inc", "yml", ".asm", \
                          ".asm16", ".asl", ".vfr", ".s", ".S", ".aslc", ".nasm", ".nasmb", ".idf", ".Vfr", ".H"]
