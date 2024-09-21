//Viktor Listi 200202273397
//vili22@student.bth.se
#include <fstream>
#include <iostream>
#include <string>
#include <filesystem>
#include <cmath>
#include <algorithm>
#include <dirent.h>

std::vector<std::string> fileRecursive(std::string path) {
    std::vector<std::string> files;
    DIR* dirpath = opendir(path.c_str());
    struct dirent* dir;

    while ((dir = readdir(dirpath)) != NULL) {
        std::string filename = dir->d_name;
        std::string filePath = "";

        if ((filename == ".") || (filename == "..")) {
            continue;
        }
        if (dir->d_type == DT_DIR) {
            filePath = path + "/" + filename;

            std::vector<std::string> subFiles = fileRecursive(filePath);
            files.insert(files.end(), subFiles.begin(), subFiles.end());
        }
        else {
            filePath = path + "/" + filename;
            files.push_back(filePath);
        }
    }
    closedir(dirpath);

    return files;
}

void flagFiles(std::vector<std::string> convertedHexVirusDescriptionVector, std::vector<std::string> virusNameVector, std::string fileLog, std::vector<std::string> files, std::vector<std::string> unconvertedHexVirusDescriptionVector) {
    std::vector<std::string> flaggedFilesVector;
    std::fstream logFile;
    std::fstream file;

    for (int i = 0; i < files.size(); i++) {
        for (int x = 0; x < virusNameVector.size(); x++) {
            if (files[i].find(virusNameVector[x]) != std::string::npos) {
                if (virusNameVector[x].length() > 0) {
                    flaggedFilesVector.push_back(files[i] + " - " + virusNameVector[x] + "=" + unconvertedHexVirusDescriptionVector[x]);
                }
            }
        }
    }

    for (int i = 0; i < files.size(); i++) {
        file.open(files[i], std::ios::in);
        std::string line;
        std::string tempFileString = "";

        while (std::getline(file, line)) {
            tempFileString += line + "\n";
        }
        file.close();

        for (int x = 0; x < convertedHexVirusDescriptionVector.size(); x++) {
            std::string fileStart = tempFileString.substr(0, convertedHexVirusDescriptionVector[x].length());
            if (convertedHexVirusDescriptionVector[x] == fileStart) {
                if (convertedHexVirusDescriptionVector[x].length() > 0) {
                    flaggedFilesVector.push_back(files[i] + " - " + virusNameVector[x] + "=" + unconvertedHexVirusDescriptionVector[x]);
                }
            }
        }
    }
    std::sort(flaggedFilesVector.begin(), flaggedFilesVector.end());
    flaggedFilesVector.erase(std::unique(flaggedFilesVector.begin(), flaggedFilesVector.end()), flaggedFilesVector.end());

    logFile.open(fileLog, std::ios::out);
    for (int i = 0; i < flaggedFilesVector.size(); i++) {
        logFile << flaggedFilesVector[i] + "\n";
    }
    logFile.close();
}

std::vector<std::string> convertHex(std::vector<std::string> unconvertedHex) {
    std::vector<std::string> convertedHex;

    for (int i = 0; i < unconvertedHex.size(); i++) {
        std::string convertedLinesTemp = "";

        for (int z = 0; z < unconvertedHex[i].size(); z += 2) {

            int decVal = 0;
            int g = 1;
            int x = 0;

            while (x < 2) {
                if (unconvertedHex[i][z + x] >= 48 && unconvertedHex[i][z + x] <= 57) {
                    decVal += (unconvertedHex[i][z + x] - 48) * pow(16, g);
                }
                else if (unconvertedHex[i][z + x] >= 97 && unconvertedHex[i][z + x] <= 102) {
                    decVal += (unconvertedHex[i][z + x] - 87) * pow(16, g);
                }
                else if (unconvertedHex[i][z + x] >= 65 && unconvertedHex[i][z + x] <= 70) {
                    decVal += (unconvertedHex[i][z + x] - 55) * pow(16, g);
                }
                else {
                    std::cout << "DATABASE ERROR! SYNTAX ERROR! ";
                    exit(0);
                }
                g--;
                x++;
            }
            convertedLinesTemp += char(decVal);
        }
        convertedHex.push_back(convertedLinesTemp);
    }
    return convertedHex;
}

std::vector<std::string> virusNames(std::string virusFile) {
    std::vector<std::string> virusNames;
    std::string lines;
    std::fstream file;

    file.open(virusFile, std::ios::in);
    while (std::getline(file, lines, '=')) {
        virusNames.push_back(lines);
        std::getline(file, lines);
    }
    virusNames.push_back(lines);
    file.close();

    return virusNames;
}


std::vector<std::string> virusDescriptions(std::string virusFile) {
    std::vector<std::string> virusDescriptions;
    std::string lines;
    std::fstream file;

    file.open(virusFile, std::ios::in);
    while (std::getline(file, lines, '=')) {
        std::getline(file, lines);
        virusDescriptions.push_back(lines);
    }
    virusDescriptions.push_back(lines);
    file.close();

    return virusDescriptions;
}

int main(int argc, char *argv[]) {
    std::string filepath;
    std::fstream file, virusFile;
    std::string virusDatabase;

    if (argc >= 2) {
        filepath = argv[1];
    }
    else {
        std::cout << "FOLDER PATH: ";
        std::cin >> filepath;
    }

    std::cout << "DATABASE PATH: ";
    std::cin >> virusDatabase;

    file.open("DV1667.txt", std::ios::out);
    if (!file) {
        std::cout << "Error, log file creation error" << std::endl;
    }
    virusFile.open(virusDatabase, std::ios::in);
    if (!virusFile) {
        std::cout << "Error, Could not open database!" << std::endl;
    }
    if (!std::filesystem::exists(filepath)) {
        std::cout << "File path error, Could not open file path!" << std::endl;
    }
    if (std::filesystem::exists(filepath) && virusFile && file) {
        flagFiles(convertHex(virusDescriptions(virusDatabase)), virusNames(virusDatabase), "DV1667.txt", fileRecursive(filepath), virusDescriptions(virusDatabase));
    }
    else {
        std::cout << "PROGRAM COULD NOT RUN, CLOSING PROGRAM! " << std::endl;
    }
    virusFile.close();
    file.close();

    return 0;
}

