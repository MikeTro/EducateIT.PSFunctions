# ===========================================================================
# LogFunctions.Tests.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Pester tests for LogFunctions.ps1
#
# History:
#   V1.0 - 17.10.2025 - M.Trojahn - Initial creation
#									 
#
#
# ===========================================================================
# Requires -Module Pester -Version 5.5.5

BeforeAll {
    # Dummy DLL for mocks (so that no real log4net DLL is necessary)
    class DummyLogManager {
        static [void] ResetConfiguration() {}
        static [object] GetLogger([string] $name) { return "MockLogger" }
    }
    class DummyBasicConfigurator {
        static [void] Configure([object] $appender) {}
    }

    # Inject mock classes
    Add-Type -TypeDefinition @"
namespace log4net {
    public class LogManager {
        public static void ResetConfiguration() {}
        public static object GetLogger(string name) { return "MockLogger"; }
    }
    public class Config {
        public class BasicConfigurator {
            public static void Configure(object appender) {}
        }
    }
    public class Layout {
        public class PatternLayout {
            public PatternLayout(string pattern) {}
        }
    }
    public class Appender {
        public class FileAppender {
            public object Layout;
            public string File;
            public bool AppendToFile;
            public string Name;
            public object LockingModel;
            public object Threshold;
            public void ActivateOptions() {}
            public class MinimalLock {}
        }
        public class RollingFileAppender : FileAppender {
            public bool StaticLogFileName;
            public bool PreserveLogFileNameExtension;
            public string MaximumFileSize;
            public string DatePattern;
            public object RollingStyle;
            public int MaxSizeRollBackups;
        }
        public class ColoredConsoleAppender {
            public object Layout;
            public object Threshold;
            public void AddMapping(object mapping) {}
            public void ActivateOptions() {}
            public class LevelColors {
                public object Level;
                public object ForeColor;
            }
            public enum Colors {
                Green, White, Yellow, Red, HighIntensity
            }
        }
    }
    public class Core {
        public class Level {
            public static object All = "All";
            public static object Debug = "Debug";
            public static object Info = "Info";
            public static object Warn = "Warn";
            public static object Error = "Error";
            public static object Fatal = "Fatal";
        }
    }
}
"@
}

Describe 'New-EitLogger' -Tag 'Unit' {
    Context 'when only console logger is created (no file)' {
        It 'returns a logger instance' {
            $result = New-EitLogger
            $result | Should -Be 'MockLogger'
        }
    }

    Context 'when file logger is created with default rolling' {
        It 'returns a logger instance and uses RollingFileAppender' {
            $result = New-EitLogger -logFilePath 'C:\temp\test.log'
            $result | Should -Be 'MockLogger'
        }
    }

    Context 'when file logger is created without rolling' {
        It 'returns a logger instance and uses FileAppender' {
            $result = New-EitLogger -logFilePath 'C:\temp\test.log' -enableRolling:$false
            $result | Should -Be 'MockLogger'
        }
    }

    Context 'when UTC logging is enabled' {
        It 'returns a logger with UTC layout' {
            $result = New-EitLogger -logUTC:$true
            $result | Should -Be 'MockLogger'
        }
    }
   
}
