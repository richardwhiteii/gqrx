#ifndef REMOTE_CONTROL_HTTPS_H
#define REMOTE_CONTROL_HTTPS_H

#include <QObject>
#include <QTcpServer>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QMap>

class RemoteControlHttps : public QObject
{
    Q_OBJECT

public:
    explicit RemoteControlHttps(QObject *parent = nullptr);
    ~RemoteControlHttps();

    void startServer(int port, const QString &certFilePath, const QString &keyFilePath);
    void stopServer();

private slots:
    void handleNewConnection();
    void handleEncryptedConnection();
    void handleReadyRead();

private:
    void sendErrorResponse(QSslSocket *clientConnection, const QString &errorMessage);
    bool isValidToken(const QString &token);
    QString generateToken();

    void handleFrequencyEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj);
    void handleDemodulatorEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj);
    void handleSignalStrengthEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj);
    void handleSquelchThresholdEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj);
    void handleAudioRecorderStatusEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj);
    void handleAosEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj);
    void handleLosEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj);

    QTcpServer *httpsServer;
    QSslConfiguration *sslConfiguration;
    QMap<QString, qint64> tokenMap;
    qint64 tokenExpirationTime;

    qint64 currentFrequency;
    QString currentDemodulator;
    double currentSignalStrength;
    double currentSquelchThreshold;
    bool audioRecorderStatus;
};

#endif // REMOTE_CONTROL_HTTPS_H
