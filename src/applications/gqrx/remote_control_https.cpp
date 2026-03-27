#include "remote_control_https.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QJsonParseError>
#include <QFile>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslCertificate>
#include <QCryptographicHash>
#include <QDateTime>
#include <QTimer>

RemoteControlHttps::RemoteControlHttps(QObject *parent) :
    QObject(parent),
    httpsServer(new QTcpServer(this)),
    sslConfiguration(new QSslConfiguration),
    tokenExpirationTime(3600) // Token expiration time in seconds (1 hour)
{
    connect(httpsServer, &QTcpServer::newConnection, this, &RemoteControlHttps::handleNewConnection);
}

RemoteControlHttps::~RemoteControlHttps()
{
    stopServer();
}

void RemoteControlHttps::startServer(int port, const QString &certFilePath, const QString &keyFilePath)
{
    // Load SSL certificate and key
    QFile certFile(certFilePath);
    QFile keyFile(keyFilePath);

    if (!certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly))
    {
        qWarning() << "Failed to open certificate or key file.";
        return;
    }

    QSslCertificate certificate(&certFile, QSsl::Pem);
    QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem);

    sslConfiguration->setLocalCertificate(certificate);
    sslConfiguration->setPrivateKey(key);
    sslConfiguration->setPeerVerifyMode(QSslSocket::VerifyNone);

    httpsServer->setSslConfiguration(*sslConfiguration);

    if (!httpsServer->listen(QHostAddress::Any, port))
    {
        qWarning() << "Failed to start HTTPS server.";
        return;
    }

    qDebug() << "HTTPS server started on port" << port;
}

void RemoteControlHttps::stopServer()
{
    if (httpsServer->isListening())
    {
        httpsServer->close();
        qDebug() << "HTTPS server stopped.";
    }
}

void RemoteControlHttps::handleNewConnection()
{
    QSslSocket *clientConnection = qobject_cast<QSslSocket *>(httpsServer->nextPendingConnection());

    if (!clientConnection)
    {
        qWarning() << "Failed to get new connection.";
        return;
    }

    connect(clientConnection, &QSslSocket::encrypted, this, &RemoteControlHttps::handleEncryptedConnection);
    connect(clientConnection, &QSslSocket::disconnected, clientConnection, &QSslSocket::deleteLater);

    clientConnection->startServerEncryption();
}

void RemoteControlHttps::handleEncryptedConnection()
{
    QSslSocket *clientConnection = qobject_cast<QSslSocket *>(sender());

    if (!clientConnection)
    {
        qWarning() << "Failed to get encrypted connection.";
        return;
    }

    connect(clientConnection, &QSslSocket::readyRead, this, &RemoteControlHttps::handleReadyRead);
}

void RemoteControlHttps::handleReadyRead()
{
    QSslSocket *clientConnection = qobject_cast<QSslSocket *>(sender());

    if (!clientConnection)
    {
        qWarning() << "Failed to get ready read connection.";
        return;
    }

    QByteArray requestData = clientConnection->readAll();
    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(requestData, &parseError);

    if (parseError.error != QJsonParseError::NoError)
    {
        qWarning() << "Failed to parse JSON request:" << parseError.errorString();
        sendErrorResponse(clientConnection, "Invalid JSON request.");
        return;
    }

    QJsonObject jsonObj = jsonDoc.object();
    QString endpoint = jsonObj.value("endpoint").toString();
    QString token = jsonObj.value("token").toString();

    if (!isValidToken(token))
    {
        sendErrorResponse(clientConnection, "Invalid or expired token.");
        return;
    }

    if (endpoint == "/frequency")
    {
        handleFrequencyEndpoint(clientConnection, jsonObj);
    }
    else if (endpoint == "/demodulator")
    {
        handleDemodulatorEndpoint(clientConnection, jsonObj);
    }
    else if (endpoint == "/signal_strength")
    {
        handleSignalStrengthEndpoint(clientConnection, jsonObj);
    }
    else if (endpoint == "/squelch_threshold")
    {
        handleSquelchThresholdEndpoint(clientConnection, jsonObj);
    }
    else if (endpoint == "/audio_recorder_status")
    {
        handleAudioRecorderStatusEndpoint(clientConnection, jsonObj);
    }
    else if (endpoint == "/aos")
    {
        handleAosEndpoint(clientConnection, jsonObj);
    }
    else if (endpoint == "/los")
    {
        handleLosEndpoint(clientConnection, jsonObj);
    }
    else
    {
        sendErrorResponse(clientConnection, "Unknown endpoint.");
    }
}

void RemoteControlHttps::sendErrorResponse(QSslSocket *clientConnection, const QString &errorMessage)
{
    QJsonObject responseObj;
    responseObj["status"] = "error";
    responseObj["message"] = errorMessage;

    QJsonDocument responseDoc(responseObj);
    QByteArray responseData = responseDoc.toJson();

    clientConnection->write(responseData);
    clientConnection->flush();
    clientConnection->disconnectFromHost();
}

bool RemoteControlHttps::isValidToken(const QString &token)
{
    if (token.isEmpty() || !tokenMap.contains(token))
    {
        return false;
    }

    qint64 currentTime = QDateTime::currentSecsSinceEpoch();
    qint64 tokenTime = tokenMap.value(token);

    if (currentTime - tokenTime > tokenExpirationTime)
    {
        tokenMap.remove(token);
        return false;
    }

    return true;
}

QString RemoteControlHttps::generateToken()
{
    QByteArray tokenData = QCryptographicHash::hash(QDateTime::currentDateTimeUtc().toString().toUtf8(), QCryptographicHash::Sha256).toHex();
    QString token = QString::fromUtf8(tokenData);

    qint64 currentTime = QDateTime::currentSecsSinceEpoch();
    tokenMap.insert(token, currentTime);

    return token;
}

void RemoteControlHttps::handleFrequencyEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj)
{
    QString method = jsonObj.value("method").toString();

    if (method == "GET")
    {
        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["frequency"] = currentFrequency;

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else if (method == "POST")
    {
        qint64 newFrequency = jsonObj.value("frequency").toVariant().toLongLong();
        currentFrequency = newFrequency;

        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["message"] = "Frequency updated.";

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else
    {
        sendErrorResponse(clientConnection, "Invalid method for /frequency endpoint.");
    }
}

void RemoteControlHttps::handleDemodulatorEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj)
{
    QString method = jsonObj.value("method").toString();

    if (method == "GET")
    {
        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["demodulator"] = currentDemodulator;

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else if (method == "POST")
    {
        QString newDemodulator = jsonObj.value("demodulator").toString();
        currentDemodulator = newDemodulator;

        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["message"] = "Demodulator updated.";

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else
    {
        sendErrorResponse(clientConnection, "Invalid method for /demodulator endpoint.");
    }
}

void RemoteControlHttps::handleSignalStrengthEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj)
{
    QString method = jsonObj.value("method").toString();

    if (method == "GET")
    {
        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["signal_strength"] = currentSignalStrength;

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else
    {
        sendErrorResponse(clientConnection, "Invalid method for /signal_strength endpoint.");
    }
}

void RemoteControlHttps::handleSquelchThresholdEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj)
{
    QString method = jsonObj.value("method").toString();

    if (method == "GET")
    {
        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["squelch_threshold"] = currentSquelchThreshold;

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else if (method == "POST")
    {
        double newSquelchThreshold = jsonObj.value("squelch_threshold").toDouble();
        currentSquelchThreshold = newSquelchThreshold;

        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["message"] = "Squelch threshold updated.";

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else
    {
        sendErrorResponse(clientConnection, "Invalid method for /squelch_threshold endpoint.");
    }
}

void RemoteControlHttps::handleAudioRecorderStatusEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj)
{
    QString method = jsonObj.value("method").toString();

    if (method == "GET")
    {
        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["audio_recorder_status"] = audioRecorderStatus;

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else if (method == "POST")
    {
        bool newAudioRecorderStatus = jsonObj.value("audio_recorder_status").toBool();
        audioRecorderStatus = newAudioRecorderStatus;

        QJsonObject responseObj;
        responseObj["status"] = "success";
        responseObj["message"] = "Audio recorder status updated.";

        QJsonDocument responseDoc(responseObj);
        QByteArray responseData = responseDoc.toJson();

        clientConnection->write(responseData);
        clientConnection->flush();
        clientConnection->disconnectFromHost();
    }
    else
    {
        sendErrorResponse(clientConnection, "Invalid method for /audio_recorder_status endpoint.");
    }
}

void RemoteControlHttps::handleAosEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj)
{
    QJsonObject responseObj;
    responseObj["status"] = "success";
    responseObj["message"] = "AOS event received.";

    QJsonDocument responseDoc(responseObj);
    QByteArray responseData = responseDoc.toJson();

    clientConnection->write(responseData);
    clientConnection->flush();
    clientConnection->disconnectFromHost();
}

void RemoteControlHttps::handleLosEndpoint(QSslSocket *clientConnection, const QJsonObject &jsonObj)
{
    QJsonObject responseObj;
    responseObj["status"] = "success";
    responseObj["message"] = "LOS event received.";

    QJsonDocument responseDoc(responseObj);
    QByteArray responseData = responseDoc.toJson();

    clientConnection->write(responseData);
    clientConnection->flush();
    clientConnection->disconnectFromHost();
}
