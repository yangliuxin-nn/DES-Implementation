package com.assignment.file;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * This is the main window for the Des Algorithm
 */

public class MainFrame {
    private JTextArea toBeEncrypted, key, encrypted, decrypted;
    private StringBuilder s;

    public static void main(String[] args) {
        MainFrame mainFrame = new MainFrame();
        mainFrame.mainFrame();
    }

    File[] files = new File[0];

    // GUI window
    private void mainFrame() {
        JFrame frame = new JFrame("Des Algorithm");
        frame.setSize(640, 700);
        frame.setResizable(false);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        JPanel panel = new JPanel();
        panel.setLayout(null);

        // enter plainText
        JLabel jLabel1 = new JLabel("Text to be Encrypted:");
        jLabel1.setBounds(15, 5, 250, 30);
        panel.add(jLabel1);

        toBeEncrypted = new JTextArea(1000, 1000);
        toBeEncrypted.setLineWrap(true);
        // allow the JTextArea to be scrollable
        JScrollPane scrollPane = new JScrollPane(toBeEncrypted, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBounds(15, 35, 595, 100);
        panel.add(scrollPane);

        // enter key used for Des
        JLabel jLabel2 = new JLabel("Key:");
        jLabel2.setBounds(15, 133, 60, 30);
        panel.add(jLabel2);

        key = new JTextArea(1000, 1000);
        key.setLineWrap(true);
        // allow the JTextArea to be scrollable
        JScrollPane keyScrollPane = new JScrollPane(key, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        keyScrollPane.setBounds(15, 162, 595, 50);
        panel.add(keyScrollPane);

        // show encrypted message
        JLabel jLabel3 = new JLabel("Encrypted message:");
        jLabel3.setBounds(15, 210, 300, 40);
        panel.add(jLabel3);

        encrypted = new JTextArea(1000, 1000);
        encrypted.setLineWrap(true);
        // allow the JTextArea to be scrollable
        JScrollPane enScrollPane = new JScrollPane(encrypted, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        enScrollPane.setBounds(15, 242, 595, 75);
        panel.add(enScrollPane);

        // show decrypted message
        JLabel jLabel4 = new JLabel("Decrypted message:");
        jLabel4.setBounds(15, 315, 300, 30);
        panel.add(jLabel4);

        decrypted = new JTextArea(1000, 1000);
        decrypted.setLineWrap(true);
        // allow the JTextArea to be scrollable
        JScrollPane deScrollPane = new JScrollPane(decrypted, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        deScrollPane.setBounds(15, 348, 595, 75);
        panel.add(deScrollPane);

        // show the file to be encrypted
        JTextArea fileArea = new JTextArea(1000, 1000);
        fileArea.setEditable(false);
        fileArea.setBorder(BorderFactory.createTitledBorder("Files to be Encrypted or Decrypted"));
        fileArea.setBounds(15, 435, 595, 170);
        panel.add(fileArea);

        // construct the files list to be displayed on the GUI
        s = new StringBuilder();
        // record the path of files to be encrypted
        String[] fList = new String[100];

        // select a file to be encrypted
        JButton jButton = new JButton("Choose File");
        jButton.setBounds(20, 618, 100, 30);
        jButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame frame = new JFrame("Choose File");
                JFileChooser chooser = new JFileChooser();
                chooser.setMultiSelectionEnabled(true);
                chooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
                int flag = chooser.showOpenDialog(frame);
                if (flag == JFileChooser.APPROVE_OPTION) {
                    files = chooser.getSelectedFiles();
                    int count = 0;
                    for (File file : files) {
                        s.append(file.getAbsolutePath());
                        s.append(";\n");
                        fList[count] = file.getAbsolutePath();
                        count = count + 1;
                    }

                    fileArea.setText(s.toString());
                }
            }
        });
        panel.add(jButton);

        // encrypt file
        JButton enFile = new JButton("Encrypt File");
        enFile.setBounds(140, 618, 100, 30);
        enFile.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String keyEn = key.getText();
                String fileEn = fList[0];
                try {
                    TestDes testDes = new TestDes();
                    System.out.println("keyEn: " + keyEn);
                    System.out.println("fileEn: " + fileEn);
                    String encryptedFileName = testDes.encrypt(fileEn, keyEn, true);
                    encrypted.setText(encryptedFileName);
                    fileArea.setText("");
                    s = new StringBuilder();
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }
                System.out.println("-----------------------");
            }
        });
        panel.add(enFile);

        TestDes testDes = new TestDes();

        // encrypt text
        JButton enText = new JButton("Encrypt Text");
        enText.setBounds(260, 618, 105, 30);
        enText.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // get text to be encrypted or file to be encrypted
                String textEn = toBeEncrypted.getText();
                String keyEn = key.getText();
                try {
                    System.out.println("textEn: " + textEn);
                    System.out.println("keyEn: " + keyEn);
                    String afterEncryption = testDes.encrypt(textEn, keyEn, false);
                    encrypted.setText(afterEncryption);
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }
                System.out.println("-----------------------");
            }
        });
        panel.add(enText);

        // decrypt encrypted text
        JButton decryptTextButton = new JButton("Decrypt Text");
        decryptTextButton.setBounds(385, 618, 110,30);
        decryptTextButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // encrypted text decryption
                byte [] resultByte = Base64.getDecoder().decode(encrypted.getText());
                byte [] keyByte = key.getText().getBytes(StandardCharsets.UTF_8);
                String decryptedStr = testDes.decryptText(resultByte, keyByte);
                decrypted.setText(decryptedStr);
                System.out.println("----------------------- " + decryptedStr);
            }
        });
        panel.add(decryptTextButton);

        // decrypt encrypted file
        JButton decryptFileButton = new JButton("Decrypt File");
        decryptFileButton.setBounds(515, 618, 100,30);
        decryptFileButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String keyEn = key.getText();
                String fileEn = fList[0];
                TestDes testDes = new TestDes();
                System.out.println("keyEn: " + keyEn);
                System.out.println("fileEn: " + fileEn);
                try {
                    String decryptedFileName = testDes.decryptFile(fileEn, keyEn);
                    decrypted.setText("Decrypted successfully! Please see the file in: \n" + decryptedFileName);
                    fileArea.setText("");
                    s = new StringBuilder();
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }
                System.out.println("-----------------------");
            }
        });
        panel.add(decryptFileButton);

        frame.add(panel);
        frame.setVisible(true);

        frame.getContentPane().setBackground(new Color(244, 254, 254));

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
}
