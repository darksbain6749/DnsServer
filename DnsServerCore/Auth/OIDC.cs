/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
using Microsoft.AspNetCore.DataProtection;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Auth
{
    class OIDC : IComparable<OIDC>
    {
        string _client;
        string _tokenURL;
        string _authURL;
        string _secret;

        private readonly IDataProtector _protector;

        #region constructor
        public OIDC(string client, string tokenURL, string authURL, string secret)
        {
            _protector = CreateProtector();
            Client = client ?? throw new ArgumentNullException(nameof(client), "Client cannot be null.");
            TokenURL = tokenURL ?? throw new ArgumentNullException(nameof(tokenURL), "Token URL cannot be null.");
            AuthURL = authURL ?? throw new ArgumentNullException(nameof(authURL), "Auth URL cannot be null.");
            Secret = encryptSecret(secret) ?? throw new ArgumentNullException(nameof(secret), "Secret cannot be null.");
        }
        public OIDC(BinaryReader bR, AuthManager authManager)
        {
            _protector = CreateProtector();

            switch (bR.ReadByte())
            {
                case 1:
                    _client = bR.ReadShortString();
                    _tokenURL = bR.ReadString();
                    _authURL = bR.ReadString();
                    _secret = bR.ReadShortString();
                    break;
                default:
                    throw new InvalidDataException("Invalid data or version not supported.");
            }
        }
        #endregion

        #region properties
        public string Client
        {
            get { return _client; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentNullException(nameof(Client), "Client cannot be null or empty.");
                _client = value;
            }
        }
        public string TokenURL
        {
            get { return _tokenURL; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentNullException(nameof(TokenURL), "Token URL cannot be null or empty.");
                _tokenURL = value;
            }
        }
        public string AuthURL
        {
            get { return _authURL; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentNullException(nameof(AuthURL), "Auth URL cannot be null or empty.");
                _authURL = value;
            }
        }
        public string Secret
        {
            get { return _secret; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentNullException(nameof(Secret), "Secret cannot be null or empty.");
                _secret = value;
            }
        }
        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1);
            bW.WriteShortString(_client);
            bW.Write(_tokenURL);
            bW.Write(_authURL);
            bW.WriteShortString(encryptSecret(_secret));
        }
        #endregion
        #region private
        private static IDataProtector CreateProtector()
        {
            // Cross-platform key storage location (per-user)
            string keyDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "OIDC-Keys"
            );

            Directory.CreateDirectory(keyDir);

            var provider = DataProtectionProvider.Create(new DirectoryInfo(keyDir));

            return provider.CreateProtector("OIDC.Secret");
        }
        #endregion
        #region public methods
        public string encryptSecret(string secret)
        {
            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
            byte[] encryptedBytes = _protector.Protect(secretBytes);
            return Convert.ToBase64String(encryptedBytes);
        }
        public string decryptSecret(string secret)
        {
            byte[] encryptedBytes = Convert.FromBase64String(secret);
            byte[] decryptedBytes = _protector.Unprotect(encryptedBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
        public OIDC getOIDC() { return new OIDC(Client, TokenURL, AuthURL, decryptSecret(Secret)); }

        public int CompareTo(OIDC other)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}