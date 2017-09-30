using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using SshNet.TestTools.OpenSSH.Formatters;

namespace SshNet.TestTools.OpenSSH
{
    public class SshdConfig
    {
        private readonly SubsystemFormatter _subsystemFormatter;
        private readonly Int32Formatter _int32Formatter;
        private readonly BooleanFormatter _booleanFormatter;
        private readonly MatchFormatter _matchFormatter;

        private SshdConfig()
        {
            Subsystems = new List<Subsystem>();
            Matches = new List<Match>();
            LogLevel = LogLevel.Info;
            Port = 22;
            UsePAM = true;

            _booleanFormatter = new BooleanFormatter();
            _int32Formatter = new Int32Formatter();
            _matchFormatter = new MatchFormatter();
            _subsystemFormatter = new SubsystemFormatter();
        }

        /// <summary>
        /// Gets or sets the port number that sshd listens on.
        /// </summary>
        /// <value>
        /// The port number that sshd listens on. The default is 22.
        /// </value>
        public int Port { get; set; }
        /// <summary>
        /// Gets or sets a file containing a private host key used by sshd.
        /// </summary>
        /// <value>
        /// A file containing a private host key used by sshd.
        /// </value>
        public string HostKey { get; set; }
        /// <summary>
        /// Gets or sets a value specifying whether challenge-response authentication is allowed.
        /// </summary>
        /// <value>
        /// A value specifying whether challenge-response authentication is allowed. The default is <c>true</c>.
        /// </value>
        public bool ChallengeResponseAuthentication { get; set; }
        /// <summary>
        /// Gets or sets the verbosity when logging messages from sshd.
        /// </summary>
        /// <value>
        /// The verbosity when logging messages from sshd. The default is <see cref="OpenSSH.LogLevel.Info"/>.
        /// </value>
        public LogLevel LogLevel { get; set; }
        /// <summary>
        /// Gets a sets a value indicating whether the Pluggable Authentication Module interface is enabled.
        /// </summary>
        /// <value>
        /// A value indicating whether the Pluggable Authentication Module interface is enabled. The default
        /// is <c>true</c>.
        /// </value>
        public bool UsePAM { get; set; }
        public List<Subsystem> Subsystems { get; }
        /// <summary>
        /// Gets a list of conditional blocks.
        /// </summary>
        public List<Match> Matches { get; }

        public void SaveTo(TextWriter writer)
        {
            writer.WriteLine("Port " + _int32Formatter.Format(Port));
            if (HostKey != null)
                writer.WriteLine("HostKey " + HostKey);
            writer.WriteLine("ChallengeResponseAuthentication " + _booleanFormatter.Format(ChallengeResponseAuthentication));
            writer.WriteLine("LogLevel " + new LogLevelFormatter().Format(LogLevel));
            foreach (var subsystem in Subsystems)
                writer.WriteLine("Subsystem " + _subsystemFormatter.Format(subsystem));
            writer.WriteLine("UsePAM " + _booleanFormatter.Format(UsePAM));
            foreach (var match in Matches)
                _matchFormatter.Format(match, writer);
        }

        public static SshdConfig LoadFrom(Stream stream, Encoding encoding)
        {
            using (var sr = new StreamReader(stream, encoding))
            {
                var matchRegex = new Regex($@"\s*Match\s+(User\s+(?<users>[\S]+))?\s*(Address\s+(?<addresses>[\S]+))?\s*");
                var sshdConfig = new SshdConfig();

                Match currentMatchConfiguration = null;

                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    var match = matchRegex.Match(line);
                    if (match.Success)
                    {
                        var usersGroup = match.Groups["users"];
                        var addressesGroup = match.Groups["addresses"];
                        var users = usersGroup.Success ? usersGroup.Value.Split(',') : Array.Empty<string>();
                        var addresses = addressesGroup.Success ? addressesGroup.Value.Split(',') : Array.Empty<string>();

                        currentMatchConfiguration = new Match(users, addresses);
                        sshdConfig.Matches.Add(currentMatchConfiguration);
                        continue;
                    }

                    if (currentMatchConfiguration != null)
                    {
                        ProcessMatchOption(currentMatchConfiguration, line);
                    }
                    else
                    {
                        ProcessGlobalOption(sshdConfig, line);
                    }
                }

                return sshdConfig;
            }
        }

        private static void ProcessGlobalOption(SshdConfig sshdConfig, string line)
        {
            var matchOptionRegex = new Regex(@"^\s*(?<name>[\S]+)\s+(?<value>.+?){1}\s*$");

            var optionsMatch = matchOptionRegex.Match(line);
            if (!optionsMatch.Success)
                return;

            var nameGroup = optionsMatch.Groups["name"];
            var valueGroup = optionsMatch.Groups["value"];

            var name = nameGroup.Value;
            var value = valueGroup.Value;

            switch (name)
            {
                case "Port":
                    sshdConfig.Port = ToInt(value);
                    break;
                case "HostKey":
                    sshdConfig.HostKey = value;
                    break;
                case "ChallengeResponseAuthentication":
                    sshdConfig.ChallengeResponseAuthentication = ToBool(value);
                    break;
                case "LogLevel":
                    sshdConfig.LogLevel = (LogLevel) Enum.Parse(typeof(LogLevel), value, true);
                    break;
                case "Subsystem":
                    sshdConfig.Subsystems.Add(Subsystem.FromConfig(value));
                    break;
                case "UsePAM":
                    sshdConfig.UsePAM = ToBool(value);
                    break;
                default:
                    throw new Exception($"Global option '{name}' is not implemented.");
            }
        }

        private static void ProcessMatchOption(Match matchConfiguration, string line)
        {
            var matchOptionRegex = new Regex(@"^\s+(?<name>[\S]+)\s+(?<value>.+?){1}\s*$");

            var optionsMatch = matchOptionRegex.Match(line);
            if (!optionsMatch.Success)
                return;

            var nameGroup = optionsMatch.Groups["name"];
            var valueGroup = optionsMatch.Groups["value"];

            var name = nameGroup.Value;
            var value = valueGroup.Value;

            switch (name)
            {
                case "AuthenticationMethods":
                    matchConfiguration.AuthenticationMethods = value;
                    break;
                default:
                    throw new Exception($"Match option '{name}' is not implemented.");
            }
        }

        private static bool ToBool(string value)
        {
            switch (value)
            {
                case "yes":
                    return true;
                case "no":
                    return false;
                default:
                    throw new Exception($"Value '{value}' cannot be mapped to a boolean.");
            }
        }

        private static int ToInt(string value)
        {
            return int.Parse(value, NumberFormatInfo.InvariantInfo);
        }
    }
}
