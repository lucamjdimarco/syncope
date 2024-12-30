package org.apache.syncope.core.spring.utils;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.dao.AnyTypeDAO;
import org.apache.syncope.core.persistence.api.entity.*;
import org.apache.syncope.core.persistence.api.entity.user.*;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.security.Encryptor;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public class ConcreteUser implements User {
    private String status;
    private String username;
    private String password;
    private String clearPassword;
    private CipherAlgorithm cipherAlgorithm;
    private Boolean mustChangePassword = false;

    @Override
    public OffsetDateTime getCreationDate() {
        return null;
    }

    @Override
    public String getCreator() {
        return null;
    }

    @Override
    public String getCreationContext() {
        return null;
    }

    @Override
    public OffsetDateTime getLastChangeDate() {
        return null;
    }

    @Override
    public String getLastModifier() {
        return null;
    }

    @Override
    public String getLastChangeContext() {
        return null;
    }

    @Override
    public void setCreationDate(OffsetDateTime creationDate) {

    }

    @Override
    public void setCreator(String creator) {

    }

    @Override
    public void setCreationContext(String context) {

    }

    @Override
    public void setLastChangeDate(OffsetDateTime lastChangeDate) {

    }

    @Override
    public void setLastModifier(String lastModifier) {

    }

    @Override
    public void setLastChangeContext(String context) {

    }

    @Override
    public AnyType getType() {
        return ApplicationContextProvider.getBeanFactory().getBean(AnyTypeDAO.class).findUser();
    }

    @Override
    public void setType(AnyType type) {
        // nothing to do
    }

    @Override
    public Realm getRealm() {
        return null;
    }

    @Override
    public void setRealm(Realm realm) {

    }

    @Override
    public String getStatus() {
        return status;
    }

    @Override
    public void setStatus(final String status) {
        this.status = status;
    }

    @Override
    public boolean add(ExternalResource resource) {
        return false;
    }

    @Override
    public List<? extends ExternalResource> getResources() {
        return null;
    }

    @Override
    public boolean add(AnyTypeClass auxClass) {
        return false;
    }

    @Override
    public List<? extends AnyTypeClass> getAuxClasses() {
        return null;
    }

    @Override
    public boolean add(UPlainAttr attr) {
        return false;
    }

    @Override
    public boolean remove(UPlainAttr attr) {
        return false;
    }

    @Override
    public Optional<? extends UPlainAttr> getPlainAttr(String plainSchema) {
        return Optional.empty();
    }

    @Override
    public List<? extends UPlainAttr> getPlainAttrs() {
        return null;
    }

    @Override
    public String getKey() {
        return null;
    }

    @Override
    public Optional<? extends UPlainAttr> getPlainAttr(String plainSchema, Membership<?> membership) {
        return Optional.empty();
    }

    @Override
    public Collection<? extends UPlainAttr> getPlainAttrs(String plainSchema) {
        return null;
    }

    @Override
    public Collection<? extends UPlainAttr> getPlainAttrs(Membership<?> membership) {
        return null;
    }

    @Override
    public boolean add(UMembership membership) {
        return false;
    }

    @Override
    public boolean remove(UMembership membership) {
        return false;
    }

    @Override
    public Optional<? extends UMembership> getMembership(String groupKey) {
        return Optional.empty();
    }

    @Override
    public List<? extends UMembership> getMemberships() {
        return null;
    }

    @Override
    public boolean add(URelationship relationship) {
        return false;
    }

    @Override
    public Optional<? extends URelationship> getRelationship(RelationshipType relationshipType, String otherEndKey) {
        return Optional.empty();
    }

    @Override
    public Collection<? extends URelationship> getRelationships(String otherEndKey) {
        return null;
    }

    @Override
    public Collection<? extends URelationship> getRelationships(RelationshipType relationshipType) {
        return null;
    }

    @Override
    public List<? extends URelationship> getRelationships() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(final String username) {
        this.username = username;
    }

    @Override
    public boolean canDecodeSecrets() {
        return this.cipherAlgorithm != null && this.cipherAlgorithm.isInvertible();
    }


    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getClearPassword() {
        return clearPassword;
    }

    public void setClearPassword(final String clearPassword) {
        this.clearPassword = clearPassword;
    }

    @Override
    public void removeClearPassword() {
        setClearPassword(null);
    }

    @Override
    public void setEncodedPassword(final String password, final CipherAlgorithm cipherAlgorithm) {
        this.password = password;
        this.cipherAlgorithm = cipherAlgorithm;
        setMustChangePassword(false);
    }

    @Override
    public void setPassword(final String password) {
        this.clearPassword = password;

        try {
            this.password = Encryptor.getInstance().encode(password, CipherAlgorithm.AES);
            setMustChangePassword(false);
        } catch (Exception e) {
            System.out.println("Could not encode password "+ e.getMessage());
            this.password = null;
        }
    }

    @Override
    public CipherAlgorithm getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    @Override
    public void setCipherAlgorithm(final CipherAlgorithm cipherAlgorithm) {
        if (this.cipherAlgorithm == null || cipherAlgorithm == null) {
            this.cipherAlgorithm = cipherAlgorithm;
        } else {
            throw new IllegalArgumentException("Cannot override existing cipher algorithm");
        }
    }

    @Override
    public Boolean isSuspended() {
        return null;
    }

    @Override
    public void setSuspended(Boolean suspended) {

    }

    @Override
    public String getToken() {
        return null;
    }

    @Override
    public OffsetDateTime getTokenExpireTime() {
        return null;
    }

    @Override
    public void generateToken(int tokenLength, int tokenExpireTime) {

    }

    @Override
    public void removeToken() {

    }

    @Override
    public boolean checkToken(String token) {
        return false;
    }

    @Override
    public boolean hasTokenExpired() {
        return false;
    }


    @Override
    public OffsetDateTime getChangePwdDate() {
        return null;
    }

    @Override
    public void setChangePwdDate(OffsetDateTime changePwdDate) {

    }

    @Override
    public void addToPasswordHistory(String password) {

    }

    @Override
    public void removeOldestEntriesFromPasswordHistory(int n) {

    }

    @Override
    public List<String> getPasswordHistory() {
        return null;
    }

    @Override
    public SecurityQuestion getSecurityQuestion() {
        return null;
    }

    @Override
    public void setSecurityQuestion(SecurityQuestion securityQuestion) {

    }

    @Override
    public String getSecurityAnswer() {
        return null;
    }

    @Override
    public String getClearSecurityAnswer() {
        return null;
    }

    @Override
    public void setEncodedSecurityAnswer(String securityAnswer) {

    }

    @Override
    public void setSecurityAnswer(String securityAnswer) {

    }

    @Override
    public Integer getFailedLogins() {
        return null;
    }

    @Override
    public void setFailedLogins(Integer failedLogins) {

    }

    @Override
    public OffsetDateTime getLastLoginDate() {
        return null;
    }

    @Override
    public void setLastLoginDate(OffsetDateTime lastLoginDate) {

    }

    @Override
    public boolean isMustChangePassword() {
        return mustChangePassword;
    }

    @Override
    public void setMustChangePassword(final boolean mustChangePassword) {
        this.mustChangePassword = mustChangePassword;
    }

    @Override
    public boolean add(Role role) {
        return false;
    }

    @Override
    public List<? extends Role> getRoles() {
        return null;
    }

    @Override
    public boolean add(LinkedAccount account) {
        return false;
    }

    @Override
    public Optional<? extends LinkedAccount> getLinkedAccount(String resource, String connObjectKeyValue) {
        return Optional.empty();
    }

    @Override
    public List<? extends LinkedAccount> getLinkedAccounts(String resource) {
        return null;
    }

    @Override
    public List<? extends LinkedAccount> getLinkedAccounts() {
        return null;
    }
}