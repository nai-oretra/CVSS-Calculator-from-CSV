import csv # Import de la fonction csv permettant d'ouvrir/lire/modifier un fichier csv | pip install csv
from cvss import CVSS3, CVSS2 #Import de la fonction CVSS permetant le calcul de la norme CVSS | pip install cvss
from datetime import datetime #import de la fonction permettant de récuperer la date | pip install datetime

def CVSS_calculator():
# Création du nom du fichier csv qui sera crée au format YYYY_MM_DD_Nessus.csv
    currentDate = str(datetime.now().year) + "_" + str(datetime.now().month) + "_" + str(datetime.now().day)
    filename = currentDate + "_Nessus.csv" # Construction du nom final
    #Fonction d'extract du fichier source afin de calculer le score CVSS et de l'inscrire dans un nouveau fichier
    with open("extract.csv", "r", newline="", encoding="utf-8") as file: # Ouvre le document
        reader = csv.DictReader(file, delimiter=";", quotechar='"')
        with open(filename, "w", newline="", encoding="utf-8") as output_file:
            fieldnames = reader.fieldnames + ["score_contextualise_v3", "vecteur_contextualise_v3", "score_contextualise_v2", "vecteur_contextualise_v2"]
            writer = csv.DictWriter(output_file, fieldnames=fieldnames, delimiter=";")
            writer.writeheader()
            for row in reader:
                if row['CVSS_V3_Vector']:
                    #print (("Ligne"), ligne,(" : \n"))
                    #print(("Valeur Tempo: "), row['CVSS_V3_Vector'])
                    cvss_v3 = "CVSS:3.0/" + row['CVSS_V3_Vector'] + '/CR:H/IR:H/AR:H/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X'
                    #print(("Vecteur recalculé :"), cvss)
                    sv3 = CVSS3(cvss_v3)
                    row["score_contextualise_v3"] = sv3.environmental_score
                    row["vecteur_contextualise_v3"] = cvss_v3
                    #print(("Score CVSSV3 recalculé : "), sv3.environmental_score, ("\n\n"))
                if row['CVSS_V2_Vector']:
                    cvss2 = row["CVSS_V2_Vector"] + '/CDP:ND/TD:ND/CR:H/IR:H/AR:H'
                    #print(("Vecteur v2 recalculé :"), cvss2)
                    sv2 = CVSS2(cvss2)
                    row["score_contextualise_v2"] = sv2.environmental_score
                    row["vecteur_contextualise_v2"] = cvss2
                    #print(("Score CVSSV2 recalculé : "), sv2.environmental_score, ("\n\n"))
                writer.writerow(row)
    print ("Fichier crée : ", filename)
CVSS_calculator()