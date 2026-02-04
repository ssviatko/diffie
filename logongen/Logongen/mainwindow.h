#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "sha2.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QString getPWforPIN(int a_pin, QString a_passphrase, bool a_updatehashes);

private slots:
    void on_btnGenerate_clicked();

    void on_btnCopy_clicked();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
