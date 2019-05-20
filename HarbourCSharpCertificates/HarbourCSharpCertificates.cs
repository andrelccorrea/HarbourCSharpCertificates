using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace HarbourCSharpCertificates
{
    [ClassInterface(ClassInterfaceType.AutoDual)]
    [ProgId("HarbourCSharpCertificates.HarbourCSharpCertificates")]
    [ComVisible(true)]
    public class HarbourCSharpCertificates
    {

        public HarbourCSharpCertificates() { }

        private void AssinarXml(string arquivo, string tagAssinatura, string tagAtributoId, X509Certificate2 x509Cert)
        {
            StreamReader SR = null;

            try
            {
                SR = File.OpenText(arquivo);
                string xmlString = SR.ReadToEnd();
                SR.Close();
                SR = null;

                // Create a new XML document.
                XmlDocument doc = new XmlDocument();

                // Format the document to ignore white spaces.
                doc.PreserveWhitespace = false;

                // Load the passed XML file using it’s name.
                doc.LoadXml(xmlString);

                if (doc.GetElementsByTagName(tagAssinatura).Count == 0)
                {
                    throw new Exception("A tag de assinatura " + tagAssinatura.Trim() + " não existe no XML. (Código do Erro: 5)");
                }
                else if (doc.GetElementsByTagName(tagAtributoId).Count == 0)
                {
                    throw new Exception("A tag de assinatura " + tagAtributoId.Trim() + " não existe no XML. (Código do Erro: 4)");
                }
                else
                {
                    XmlDocument XMLDoc;

                    XmlNodeList lists = doc.GetElementsByTagName(tagAssinatura);
                    foreach (XmlNode nodes in lists)
                    {
                        foreach (XmlNode childNodes in nodes.ChildNodes)
                        {
                            if (!childNodes.Name.Equals(tagAtributoId))
                                continue;

                            if (childNodes.NextSibling != null && childNodes.NextSibling.Name.Equals("Signature"))
                                continue;

                            // Create a reference to be signed
                            Reference reference = new Reference();
                            reference.Uri = "";

                            XmlElement childElemen = (XmlElement)childNodes;
                            if (childElemen.GetAttributeNode("Id") != null)
                            {
                                reference.Uri = ""; // "#" + childElemen.GetAttributeNode("Id").Value;
                            }
                            else if (childElemen.GetAttributeNode("id") != null)
                            {
                                reference.Uri = "#" + childElemen.GetAttributeNode("id").Value;
                            }

                            // Create a SignedXml object.
                            SignedXml signedXml = new SignedXml(doc);

                            // Add the key to the SignedXml document
                            signedXml.SigningKey = x509Cert.PrivateKey;

                            // Add an enveloped transformation to the reference.
                            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
                            reference.AddTransform(env);

                            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
                            reference.AddTransform(c14);

                            // Add the reference to the SignedXml object.
                            signedXml.AddReference(reference);

                            // Create a new KeyInfo object
                            KeyInfo keyInfo = new KeyInfo();

                            // Load the certificate into a KeyInfoX509Data object
                            // and add it to the KeyInfo object.
                            keyInfo.AddClause(new KeyInfoX509Data(x509Cert));

                            // Add the KeyInfo object to the SignedXml object.
                            signedXml.KeyInfo = keyInfo;
                            signedXml.ComputeSignature();

                            // Get the XML representation of the signature and save
                            // it to an XmlElement object.
                            XmlElement xmlDigitalSignature = signedXml.GetXml();

                            nodes.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                        }
                    }

                    XMLDoc = new XmlDocument();
                    XMLDoc.PreserveWhitespace = false;
                    XMLDoc = doc;

                    string conteudoXMLAssinado = XMLDoc.OuterXml;

                    using (StreamWriter sw = File.CreateText(arquivo))
                    {
                        sw.Write(conteudoXMLAssinado);
                        sw.Close();
                    }
                }
            }
            finally
            {
                if (SR != null)
                    SR.Close();
            }
        }

    }
}
