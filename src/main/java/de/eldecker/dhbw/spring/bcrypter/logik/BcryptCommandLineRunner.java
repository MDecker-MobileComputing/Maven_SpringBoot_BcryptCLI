package de.eldecker.dhbw.spring.bcrypter.logik;

import static org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion.$2B;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.Scanner;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class BcryptCommandLineRunner implements CommandLineRunner {

    /** Sicherer Zufallsgenerator für Salt-Erzeugung. */
    final SecureRandom _zufallsgenerator = new SecureRandom();

    /** Text-Scanner für Einlesen Nutzereingaben. */
    final Scanner _scanner = new Scanner( System.in );
    
    
    /**
     * Diese Methode wird beim Programmstart automatisch aufgerufen.
     * Wenn diese Methode beendet ist, dann wird das Programm beendet. 
     * 
     * @param args Wird nicht ausgewertet
     */
    public void run( String... args ) throws Exception {

        final Optional<String> passwortOptional = passwortEinlesen();
        if ( passwortOptional.isEmpty() ) { return; }
        
    
        final String passwort = passwortOptional.get();
                
        final BCryptPasswordEncoder bcryptEncoder = new BCryptPasswordEncoder( $2B, 4, _zufallsgenerator );
        
        final String hashwert = bcryptEncoder.encode( passwort ) ;
        
        System.out.println( "\nHashwert: " + hashwert ); 
    }
    
    
    /**
     * Liest Passwort von der Tastatur ein.
     * 
     * @return Optional ist leer, wenn Nutzer leeren String eingegeben hat; ansonsten
     *         ist das "getrimmte" Passwort enthalten.  
     */
    private Optional<String> passwortEinlesen() {
     
        System.out.print ( "\nPasswort zum Verhaschen mit Bcrypt eingeben > " );        
        String nutzereingabeString1 = _scanner.nextLine();
        
        nutzereingabeString1 = nutzereingabeString1.trim();
        if ( nutzereingabeString1.isBlank() ) {
            
            System.out.println( "FEHLER: Leeres Passwort eingegeben" );
            return Optional.empty();
            
        } else {
            
            final int anzZeichen = nutzereingabeString1.length();
            System.out.println( "\nAnzahl Zeichen von Passwort: " + anzZeichen );
            
            return Optional.of( nutzereingabeString1 );
        }
    }
    
}