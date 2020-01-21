using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SshNet.TestTools.OpenSSH.Formatters;

namespace SshNet.TestTools.OpenSSH
{
    public class SshdConfig
    {
        private static readonly Regex matchRegex = new Regex($@"\s*Match\s+(User\s+(?<users>[\S]+))?\s*(Address\s+(?<addresses>[\S]+))?\s*", RegexOptions.Compiled);

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
            AcceptedEnvironmentVariables = new List<string>();

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
        public bool X11Forwarding { get; private set; }
        public List<string> AcceptedEnvironmentVariables { get; private set; }
        public List<Cipher> Ciphers { get; private set; }
        public List<HostKeyAlgorithm> HostKeyAlgorithms { get; private set; }
        public List<KeyExchangeAlgorithm> KeyExchangeAlgorithms { get; private set; }
        public List<MessageAuthenticationCodeAlgorithm> MessageAuthenticationCodeAlgorithms { get; private set; }

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
            writer.WriteLine("X11Forwarding " + _booleanFormatter.Format(X11Forwarding));
            foreach (var match in Matches)
                _matchFormatter.Format(match, writer);
            foreach (var acceptedEnvVar in AcceptedEnvironmentVariables)
                writer.WriteLine("AcceptEnv " + acceptedEnvVar);

            if (Ciphers.Count > 0)
            {
                writer.WriteLine("Ciphers " + string.Join(",", Ciphers));
            }

            if (HostKeyAlgorithms.Count > 0)
            {
                writer.WriteLine("HostKeyAlgorithms " + string.Join(",", HostKeyAlgorithms));
            }

            if (KeyExchangeAlgorithms.Count > 0)
            {
                writer.WriteLine("KexAlgorithms " + string.Join(",", KeyExchangeAlgorithms));
            }

            if (MessageAuthenticationCodeAlgorithms.Count > 0)
            {
                writer.WriteLine("MACs " + string.Join(",", MessageAuthenticationCodeAlgorithms));
            }
        }

        public static SshdConfig LoadFrom(Stream stream, Encoding encoding)
        {
            using (var sr = new StreamReader(stream, encoding))
            {
                var sshdConfig = new SshdConfig();

                Match currentMatchConfiguration = null;

                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    // Skip empty lines
                    if (line.Length == 0)
                    {
                        continue;
                    }

                    // Skip comments
                    if (line[0] == '#')
                    {
                        continue;
                    }

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

                if (sshdConfig.Ciphers == null)
                {
                    // Obtain supported ciphers using ssh -Q cipher
                }

                if (sshdConfig.KeyExchangeAlgorithms == null)
                {
                    // Obtain supports key exchange algorithms using ssh -Q kex
                }

                if (sshdConfig.HostKeyAlgorithms == null)
                {
                    // Obtain supports host key algorithms using ssh -Q key
                }

                if (sshdConfig.MessageAuthenticationCodeAlgorithms == null)
                {
                    // Obtain supported MACs using ssh -Q mac 
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
                case "X11Forwarding":
                    sshdConfig.X11Forwarding = ToBool(value);
                    break;
                case "Ciphers":
                    sshdConfig.Ciphers = ParseCiphers(value);
                    break;
                default:
                    throw new Exception($"Global option '{name}' is not implemented.");
            }
        }

        private static List<Cipher> ParseCiphers(string value)
        {
            var cipherNames = value.Split(',');
            var ciphers = new List<Cipher>(cipherNames.Length);
            foreach (var cipherName in cipherNames)
            {
                ciphers.Add(new Cipher(cipherName.Trim()));
            }
            return ciphers;
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
