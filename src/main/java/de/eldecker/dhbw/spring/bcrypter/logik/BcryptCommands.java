package de.eldecker.dhbw.spring.bcrypter.logik;

import static org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion.$2B;

import java.security.SecureRandom;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;


@ShellComponent
public class BcryptCommands {

    /** Sicherer Zufallsgenerator */
    final SecureRandom _zufallsgenerator = new SecureRandom();

    @ShellMethod( key = "bcrypt", value = "Passwort mit Bcrypt verhashen" )
    public String bcrypt( @ShellOption String passwort,
                          @ShellOption(defaultValue = "10") int kostenFaktor ) {

        if ( kostenFaktor < 4 || kostenFaktor > 31 ) {

            return "Kostenfaktor muss zwischen 4 und 31 liegen";
        }

        final BCryptPasswordEncoder bcryptEncoder = new BCryptPasswordEncoder( $2B, kostenFaktor, _zufallsgenerator );

        return bcryptEncoder.encode( passwort );
    }

}
