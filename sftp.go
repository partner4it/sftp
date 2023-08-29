// Run a sftp connection over ssh
package sftp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/secsy/goftp"
	"golang.org/x/crypto/ssh"
)

// Config represents SSH connection parameters.
type Config struct {
	Username         string
	Password         string
	PrivateKey       string
	Server           string
	KeyExchanges     []string
	TLS              bool
	Timeout          time.Duration
	ActiveTransfers  bool
	ActiveListenAddr string
}

// Client provides basic functionality to interact with a SFTP server.
type Client struct {
	config     Config
	sshClient  *ssh.Client
	sftpClient *sftp.Client
	ftpClient  *goftp.Client
}

// New initialises SSH and SFTP clients and returns Client type to use.
func New(config Config) (*Client, error) {
	c := &Client{
		config: config,
	}

	if err := c.connect(); err != nil {
		return nil, err
	}

	return c, nil
}

// Create creates a remote/destination file for I/O.
func (c *Client) Create(filePath string) (io.ReadWriteCloser, error) {
	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if c.ftpClient != nil {
		return nil, errors.New("Create not implemented")
	}
	return c.sftpClient.Create(filePath)
}

// Remove a file or directory
func (c *Client) Remove(path string) error {
	if err := c.connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if c.ftpClient != nil {
		return c.ftpClient.Delete(path)
	}
	return c.sftpClient.Remove(path)
}

// Glob returns the names of all files matching pattern or nil if there is no matching file. The syntax of patterns is the same as in Match. The pattern may describe hierarchical names such as /usr/*/bin/ed.
// Glob ignores file system errors such as I/O errors reading directories. The only possible returned error is ErrBadPattern, when pattern is malformed.
func (c *Client) Glob(pattern string) (matches []string, err error) {
	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if c.ftpClient != nil {
		files, err := c.ftpClient.ReadDir(filepath.Dir(pattern))
		if err != nil {
			return nil, err
		}
		var matches = []string{}
		for _, remoteFile := range files {
			match, err := filepath.Match(pattern, filepath.Dir(pattern)+"/"+remoteFile.Name())
			if err != nil {
				return nil, err
			}
			if match {
				matches = append(matches, filepath.Dir(pattern)+"/"+remoteFile.Name())
			}
		}
		return matches, nil
	}
	return c.sftpClient.Glob(pattern)
}

func (c *Client) UploadFile(path string, source io.Reader) error {

	if err := c.connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	if c.ftpClient != nil {
		return c.ftpClient.Store(path, source)
	}
	// Write back the config file
	destination, err := c.Create(path)
	if err != nil {
		return err
	}
	defer destination.Close()
	// Upload the remoteconfig file to a remote location as in 1MB (byte) chunks.
	if err := c.Upload(source, destination, 1000000); err != nil {
		return err
	}
	return nil
}

// Upload writes local/source file data streams to remote/destination file.
func (c *Client) Upload(source io.Reader, destination io.Writer, size int) error {
	if err := c.connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	if c.ftpClient != nil {
		return errors.New("Upload with writer not implemented")
	}

	chunk := make([]byte, size)

	for {
		num, err := source.Read(chunk)
		if err == io.EOF {
			tot, err := destination.Write(chunk[:num])
			if err != nil {
				return err
			}

			if tot != len(chunk[:num]) {
				return fmt.Errorf("failed to write stream")
			}

			return nil
		}

		if err != nil {
			return err
		}

		tot, err := destination.Write(chunk[:num])
		if err != nil {
			return err
		}

		if tot != len(chunk[:num]) {
			return fmt.Errorf("failed to write stream")
		}
	}
}

// Download returns remote/destination file for reading.
func (c *Client) Download(filePath string) (io.ReadCloser, error) {
	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	if c.ftpClient != nil {
		const fn = ".sftp.tmp"
		tmp, err := os.Create(fn)
		if err != nil {
			return nil, err
		}
		defer tmp.Close()
		err = c.ftpClient.Retrieve(filePath, tmp)
		if err != nil {
			if strings.Contains(err.Error(), "550-Failed to open file") {
				err = os.ErrNotExist
			}
			return nil, err
		}
		//Close the temp file before removing it
		tmp.Close()
		buf, err := os.ReadFile(fn)
		os.Remove(fn)
		return io.NopCloser(bytes.NewBuffer(buf)), err
	}

	return c.sftpClient.Open(filePath)
}

// Info gets the details of a file. If the file was not found, an error is returned.
func (c *Client) Info(filePath string) (os.FileInfo, error) {
	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	if c.ftpClient != nil {
		return c.ftpClient.Stat(filePath)
	}

	info, err := c.sftpClient.Lstat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file stats: %w", err)
	}

	return info, nil
}

// Close closes open connections.
func (c *Client) Close() {
	if c.sftpClient != nil {
		c.sftpClient.Close()
	}
	if c.sshClient != nil {
		c.sshClient.Close()
	}
	if c.ftpClient != nil {
		c.ftpClient.Close()
	}
}

// connect initialises a new SSH and SFTP client only if they were not
// initialised before at all and, they were initialised but the SSH
// connection was lost for any reason.
func (c *Client) connect() error {

	//Check if we should use a tls connection
	if c.config.TLS {
		if c.ftpClient != nil {
			return nil
		}
		var err error
		// TLS client authentication
		config := tls.Config{
			InsecureSkipVerify: true,
			ServerName:         c.config.Server,
			ClientAuth:         tls.RequestClientCert,
		}
		cfg := goftp.Config{
			User:             c.config.Username,
			Password:         c.config.Password,
			Timeout:          c.config.Timeout,
			TLSConfig:        &config,
			TLSMode:          goftp.TLSExplicit, //TLSImplicit TLSExplicit
			ActiveTransfers:  c.config.ActiveTransfers,
			ActiveListenAddr: c.config.ActiveListenAddr,
		}
		c.ftpClient, err = goftp.DialConfig(cfg, c.config.Server)
		return err
	}

	//We use a SSH connection
	if c.sshClient != nil {
		_, _, err := c.sshClient.SendRequest("keepalive", false, nil)
		if err == nil {
			return nil
		}
	}
	auth := ssh.Password(c.config.Password)
	if c.config.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.config.PrivateKey))
		if err != nil {
			return fmt.Errorf("ssh parse private key: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	}

	cfg := &ssh.ClientConfig{
		User: c.config.Username,
		Auth: []ssh.AuthMethod{
			auth,
		},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error { return nil },
		Timeout:         c.config.Timeout,
		Config: ssh.Config{
			KeyExchanges: c.config.KeyExchanges,
		},
	}
	//We need port to connect
	server := c.config.Server
	if !strings.Contains(server, ":") {
		server = server + ":22"
	}
	sshClient, err := ssh.Dial("tcp", server, cfg)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	c.sshClient = sshClient
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("sftp new client: %w", err)
	}
	c.sftpClient = sftpClient
	return nil
}
