#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QString MainWindow::getPWforPIN(int a_pin, QString a_passphrase, bool a_updatehashes)
{
    const QString g_allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    int g_allowed_len = g_allowed.size();

    sha512_ctx ctx;
    QByteArray raw = a_passphrase.toUtf8();
    sha512_init(&ctx);
    sha512_update(&ctx, (unsigned char *)raw.data(), raw.size());
    QByteArray digest;
    unsigned char digest_uc[64];
    sha512_final(&ctx, digest_uc);
    digest.append((char *)digest_uc, 64);
    if (a_updatehashes)
        ui->leBaseHash->setText(digest.toBase64());
    // generate forward hash
    QByteArray forwardhash;
    forwardhash.append(digest);
    for (int i = 1; i <= a_pin; ++i) {
        QByteArray newhash;
        sha512_ctx fctx;
        sha512_init(&fctx);
        sha512_update(&fctx, (unsigned char *)forwardhash.data(), forwardhash.size());
        sha512_final(&fctx, digest_uc);
        newhash.append((char *)digest_uc, 64);
        forwardhash.clear();
        forwardhash.append(newhash);
    }
    QString forwardhash_str = forwardhash.toBase64();
    if (a_updatehashes)
        ui->leForwardHash->setPlaceholderText(forwardhash_str);

    QString l_pwout;

    // generate first char with a modulus of 26, make it a capital letter
    quint32 l_capnum = qFromLittleEndian<quint32>(forwardhash.data() + 0);
    quint8 l_capmodulus = l_capnum % 26;
    l_pwout += g_allowed.at(l_capmodulus);

    // generate second char with a modulus of 10, make it a number
    quint32 l_numnum = qFromLittleEndian<quint32>(forwardhash.data() + 4);
    quint8 l_nummodulus = l_numnum % 10;
    l_nummodulus += 52; // step over all the letters
    l_pwout += g_allowed.at(l_nummodulus);

    // generate third char with modulus of 26, mandatory lower case letter
    quint32 l_lowernum = qFromLittleEndian<quint32>(forwardhash.data() + 8);
    quint8 l_lowermodulus = l_lowernum % 26;
    l_lowermodulus += 26; // step over the caps
    l_pwout += g_allowed.at(l_lowermodulus);

    // generate 4th char as a special char
    quint32 l_specialnum = qFromLittleEndian<quint32>(forwardhash.data() + 12);
    quint8 l_specialmodulus = l_specialnum % (g_allowed_len - 62);
    l_specialmodulus += 62; // step over letters and numbers
    l_pwout += g_allowed.at(l_specialmodulus);

    // remaining characters are random from any point in the allowed character list
    for (unsigned int i = 4; i < 16; ++i) {
        quint32 l_num = qFromLittleEndian<quint32>(forwardhash.data() + (i * 4));
        quint8 l_modulus = l_num % g_allowed_len;
        l_pwout += g_allowed.at(l_modulus);
    }
    return l_pwout;
}

void MainWindow::on_btnGenerate_clicked()
{
    if (ui->lePassphrase->text() == "") {
        ui->lePassphrase->setText("default_passphrase");
    }
    QString firstpw = getPWforPIN(ui->spinPIN->value(), ui->lePassphrase->text(), true);
    ui->lePassword->setText(firstpw);
    ui->teNext16->clear();
    for (int i = ui->spinPIN->value() + 1; i < ui->spinPIN->value() + 16; ++i) {
        QString nextpw = getPWforPIN(i, ui->lePassphrase->text(), false);
        ui->teNext16->append(QString::number(i) + " = " + nextpw);
    }
}


void MainWindow::on_btnCopy_clicked()
{
    ui->lePassword->selectAll();
    ui->lePassword->copy();
}

